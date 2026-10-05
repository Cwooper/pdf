package pdf

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fontPage returns a one-page reader whose page shows content with font
// /F1, the font dictionary given, and extra objects numbered from 6.
func fontPage(t *testing.T, content, font string, extra ...string) *Reader {
	t.Helper()
	return openPDF(t, pagePDF("/Resources << /Font << /F1 5 0 R >> >>", append([]string{flateObj(content), font}, extra...)...))
}

// TestCmapDestinationCap verifies that a ToUnicode destination longer than
// the 512 bytes the CMap format allows is not kept.
func TestCmapDestinationCap(t *testing.T) {
	const space = "1 begincodespacerange <00> <ff> endcodespacerange "
	at := "<" + strings.Repeat("0041", 256) + ">"
	over := "<" + strings.Repeat("0041", 257) + ">"
	tests := []struct {
		name, cmap, want string
	}{
		{"bfchar at cap", space + "1 beginbfchar <01> " + at + " endbfchar", strings.Repeat("A", 256)},
		{"bfchar over cap", space + "1 beginbfchar <01> " + over + " endbfchar", string(noRune)},
		{"bfrange at cap", space + "1 beginbfrange <01> <02> " + at + " endbfrange", strings.Repeat("A", 256)},
		{"bfrange over cap", space + "1 beginbfrange <01> <02> " + over + " endbfrange", string(noRune)},
		{"bfrange array over cap", space + "1 beginbfrange <01> <02> [" + over + " <0042>] endbfrange", string(noRune)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := readCmap(rawStream(tt.cmap))
			if m == nil {
				t.Fatal("readCmap returned nil")
			}
			if got := m.Decode("\x01"); got != tt.want {
				t.Errorf("Decode = %d runes %.20q, want %d runes", len([]rune(got)), got, len([]rune(tt.want)))
			}
		})
	}
}

// TestCmapSharedDestination verifies that a bfrange destination array
// shared through def is not scanned again for each range naming it.
func TestCmapSharedDestination(t *testing.T) {
	const ranges = 4000
	cm := "1 begincodespacerange <0000> <ffff> endcodespacerange <<>> begin /D [" +
		strings.Repeat("<0041> ", 1<<16) + "] def " + strings.Repeat("1 beginbfrange <0000> <ffff> D endbfrange ", ranges)
	start := time.Now()
	if m := readCmap(rawStream(cm)); m == nil || m.Decode("\x00\x05") != "A" {
		t.Errorf("readCmap did not map <0005> through the shared array")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("parsing %d ranges sharing one array took %v", ranges, d)
	}
}

// TestDecodeBoundedByGlyphCap verifies that text decoding stops near the
// page's glyph cap instead of expanding a whole string first: every code
// below maps to 256 runes, so the string decodes to 64 times the cap.
func TestDecodeBoundedByGlyphCap(t *testing.T) {
	cm := "1 begincodespacerange <00> <ff> endcodespacerange 1 beginbfchar <01> <" + strings.Repeat("0041", 256) + "> endbfchar"
	content := "BT /F1 12 Tf (" + strings.Repeat("\x01", maxPageGlyphs/4) + ") Tj ET"
	r := fontPage(t, content, "<< /Type /Font /Subtype /Type1 /BaseFont /X /ToUnicode 6 0 R >>", flateObj(cm))
	p := r.Page(1)
	limit := uint64(64 << 20)

	content1 := func(p Page) func() {
		return func() { mustPanic(t, "glyphs", func() { p.Content() }) }
	}
	// Content keeps a Text per glyph up to the cap however they decode.
	base := allocated(content1(pageWithContent("BT (" + strings.Repeat("A", maxPageGlyphs+1) + ") Tj ET")))
	if got := allocated(content1(p)); got > base+limit {
		t.Errorf("Content allocated %d MB, %d MB for the cap in plain bytes", got>>20, base>>20)
	}
	var err error
	if got := allocated(func() { _, err = p.GetPlainText(nil) }); got > limit || err == nil {
		t.Errorf("GetPlainText allocated %d MB, err %v; want the glyph cap reported", got>>20, err)
	}
	if got := allocated(func() { _, err = p.GetTextByRow() }); got > limit || err == nil {
		t.Errorf("GetTextByRow allocated %d MB, err %v; want the glyph cap reported", got>>20, err)
	}
}

// TestCmapLookupScales verifies that decoding a code does not scan every
// entry of the cmap, which 30 KB of input can fill with millions of codes.
func TestCmapLookupScales(t *testing.T) {
	var cm strings.Builder
	cm.WriteString("1 begincodespacerange <000000> <ffffff> endcodespacerange\n")
	const blocks = 60
	for b := range blocks {
		cm.WriteString("1000 beginbfchar\n")
		for i := range 1000 {
			fmt.Fprintf(&cm, "<01%04x> <0041>\n", b*1000+i)
		}
		cm.WriteString("endbfchar\n1000 beginbfrange\n")
		for i := range 1000 {
			fmt.Fprintf(&cm, "<02%04x> <02%04x> <0042>\n", b*1000+i, b*1000+i)
		}
		cm.WriteString("endbfrange\n")
	}
	m := readCmap(rawStream(cm.String()))
	if m == nil {
		t.Fatal("readCmap returned nil")
	}
	codes := strings.Repeat("\x03\x00\x00", 20000)
	start := time.Now()
	if got := m.Decode(codes); got != strings.Repeat(string(noRune), 20000) {
		t.Errorf("Decode = %.20q, want only replacement characters", got)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("decoding 20000 codes against %d entries took %v", 2*blocks*1000, d)
	}
}

// TestCmapLookup verifies how codes resolve against a cmap's entries:
// bfchar before bfrange, the first of duplicate bfchar entries, and a code
// inside a range nested in another.
func TestCmapLookup(t *testing.T) {
	const cm = "4 begincodespacerange <00> <3f> <20> <5f> <66> <01> <8000> <ffff> endcodespacerange\n" +
		"1 begincodespacerange <68> <7f> endcodespacerange\n" +
		"2 beginbfchar <05> <0058> <05> <0059> endbfchar\n" +
		"1 beginbfchar <05> <005a> endbfchar\n" +
		"3 beginbfrange <00> <7f> <0061> <20> <21> [<0031> <0032>] <8000> <8001> <0041> endbfrange\n"
	m := readCmap(rawStream(cm))
	if m == nil {
		t.Fatal("readCmap returned nil")
	}
	tests := []struct{ in, want string }{
		{"\x05", "Y"},      // the first bfchar of a block is popped last
		{"\x01", "b"},      // outer range
		{"\x21", "2"},      // inner range
		{"\x22", "\u0083"}, // outer range past the inner one
		{"\x80\x01", "B"},
		{"\x50", "\u00b1"}, // overlapping codespace ranges
		{"\x64", "\ufffd"}, // between codespace ranges
		{"\x02", "c"},      // before an inverted codespace range
	}
	for _, tt := range tests {
		if got := m.Decode(tt.in); got != tt.want {
			t.Errorf("Decode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestCmapEntryCap verifies that a cmap holding more entries than a full
// CID table needs is refused, and that entries no code can match, 72 bytes
// each for 6 bytes of input, are not kept.
func TestCmapEntryCap(t *testing.T) {
	block := func(n int) string {
		var b strings.Builder
		fmt.Fprintf(&b, "%d beginbfchar\n", n)
		for i := range n {
			fmt.Fprintf(&b, "<%06x> <0041>\n", i)
		}
		b.WriteString("endbfchar\n")
		return b.String()
	}
	if m := readCmap(rawStream(block(maxCmapEntries))); m == nil {
		t.Error("readCmap refused a cmap at the entry cap")
	}
	if m := readCmap(rawStream(block(maxCmapEntries) + "1 beginbfchar <ffffff> <0041> endbfchar")); m != nil {
		t.Error("readCmap kept a cmap past the entry cap")
	}
	junk := "80000 beginbfrange " + strings.Repeat("()()()", 80000) + " endbfrange\n" +
		"100000 beginbfchar " + strings.Repeat("()()", 100000) + " endbfchar\n"
	m := readCmap(rawStream(strings.Repeat(junk, 3)))
	if m == nil || len(m.bfchar)+len(m.bfrange) != 0 {
		t.Errorf("readCmap kept unmatchable entries")
	}
}

// TestDifferencesTable verifies that a font's /Differences array is read
// once, not once per byte shown.
func TestDifferencesTable(t *testing.T) {
	const entries, shown = 200000, 2000
	r := fontPage(t, "BT /F1 12 Tf ("+strings.Repeat("B", shown)+") Tj ET",
		"<< /Type /Font /Subtype /Type1 /BaseFont /X /Encoding << /Differences 6 0 R >> >>",
		"[0 "+strings.Repeat("/q0 ", entries)+"]")
	start := time.Now()
	text, err := r.Page(1).GetPlainText(nil)
	if err != nil || text != "\n"+strings.Repeat("B", shown) {
		t.Errorf("GetPlainText = %.20q, %v", text, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("showing %d bytes against %d differences took %v", shown, entries, d)
	}
}

// TestDifferences verifies how a /Differences array maps codes.
func TestDifferences(t *testing.T) {
	diff := array{
		name("Alpha"), // before any code
		int64(65), name("Beta"), name("NotAGlyphName"), name("Gamma"),
		int64(66), name("Delta"), // the first known name for a code wins
		int64(66), name("Alpha"),
		int64(300), name("Alpha"), int64(-1), name("Alpha"),
	}
	enc := (&Font{V: testValue(dict{name("Encoding"): dict{name("Differences"): diff}})}).Encoder()
	if got, want := enc.Decode("\x00ABCD"), "\x00\u0392\u2206\u0393D"; got != want {
		t.Errorf("Decode = %q, want %q", got, want)
	}
}

// TestCIDFontWidths verifies that glyphs of a Type0 font advance by the
// widths of its descendant font, /W in both its forms and /DW for the rest.
func TestCIDFontWidths(t *testing.T) {
	const cm = "1 begincodespacerange <0000> <ffff> endcodespacerange " +
		"1 beginbfrange <0001> <0005> <0041> endbfrange " +
		"2 beginbfchar <0006> <00660069> <0007> <> endbfchar"
	type glyph struct {
		S    string
		X, W float64
	}
	tests := []struct {
		name, descendant string
		want             []glyph
	}{
		{"W and DW", "<< /Type /Font /Subtype /CIDFontType2 /W [1 [500 600] 3 4 700 6 [800]] /DW 300 >>", []glyph{
			{"A", 0, 5}, {"B", 5, 6}, {"C", 11, 7}, {"D", 18, 7}, {"E", 25, 3},
			{"f", 28, 4}, {"i", 32, 4}, {"A", 36 + 3, 5},
		}},
		{"no DW", "<< /Type /Font /Subtype /CIDFontType2 >>", []glyph{
			{"A", 0, 10}, {"B", 10, 10}, {"C", 20, 10}, {"D", 30, 10}, {"E", 40, 10},
			{"f", 50, 5}, {"i", 55, 5}, {"A", 70, 10},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := fontPage(t, "BT /F1 10 Tf <0001000200030004000500060007 0001> Tj ET",
				"<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /DescendantFonts [7 0 R] /ToUnicode 6 0 R >>",
				streamObj(cm), tt.descendant)
			var got []glyph
			for _, tx := range r.Page(1).Content().Text {
				got = append(got, glyph{tx.S, tx.X, tx.W})
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("got  %v\nwant %v", got, tt.want)
			}
		})
	}
	// The newline ending a TJ is not a code of the font and takes no width.
	t.Run("TJ end", func(t *testing.T) {
		r := fontPage(t, "BT /F1 10 Tf [<0001>] TJ <0002> Tj ET",
			"<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /DescendantFonts [7 0 R] /ToUnicode 6 0 R >>",
			streamObj(cm), tests[0].descendant)
		var got []glyph
		for _, tx := range r.Page(1).Content().Text {
			got = append(got, glyph{tx.S, tx.X, tx.W})
		}
		if want := []glyph{{"A", 0, 5}, {"\n", 5, 0}, {"B", 5, 6}}; fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("got  %v\nwant %v", got, want)
		}
	})
}

// TestCIDWidthsShared verifies that Type0 fonts sharing a descendant font
// share its widths, and that a font from Page.Font reads them once rather
// than on every Width call.
func TestCIDWidthsShared(t *testing.T) {
	const fonts = 64
	var names, content strings.Builder
	content.WriteString("BT ")
	objs := []string{"", "<< /Type /Font /Subtype /CIDFontType2 /W [0 [" + strings.Repeat("500 ", maxCIDWidths) + "]] >>"}
	for i := range fonts {
		fmt.Fprintf(&names, "/F%d %d 0 R ", i, 6+i)
		fmt.Fprintf(&content, "/F%d 10 Tf <0001> Tj ", i)
		objs = append(objs, "<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /DescendantFonts [5 0 R] >>")
	}
	objs[0] = flateObj(content.String() + "ET")
	r := openPDF(t, pagePDF("/Resources << /Font << "+names.String()+">> >>", objs...))
	var text []Text
	if got := allocated(func() { text = r.Page(1).Content().Text }); got > 32<<20 {
		t.Errorf("Content allocated %d MB", got>>20)
	}
	// Each two-byte code decodes to two runes sharing its width.
	if len(text) != 2*fonts || text[2*fonts-2].X != 5*(fonts-1) {
		t.Fatalf("Content shows %d glyphs; want %d, the last code at X %d", len(text), 2*fonts, 5*(fonts-1))
	}
	f := r.Page(1).Font("F0")
	var w float64
	if got := allocated(func() {
		for range 100 {
			w = f.Width(1)
		}
	}); got > 16<<20 || w != 500 {
		t.Errorf("100 calls to Width allocated %d MB, width %v; want 500", got>>20, w)
	}
}

// TestPlainTextFontsPerPage verifies that GetPlainText decodes each page
// with the fonts that page defines, though pages name them alike.
func TestPlainTextFontsPerPage(t *testing.T) {
	cmap := func(dst string) string {
		return streamObj("1 begincodespacerange <00> <ff> endcodespacerange 1 beginbfchar <01> <" + dst + "> endbfchar")
	}
	r := openPDF(t, buildPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R] /Count 3 >>",
		"<< /Type /Page /Parent 2 0 R /Contents 6 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /ToUnicode 9 0 R >> >> >> >>",
		"<< /Type /Page /Parent 2 0 R /Contents 6 0 R /Resources << /Font << /F1 7 0 R >> >> >>",
		"<< /Type /Page /Parent 2 0 R /Contents 6 0 R /Resources << /Font << /F1 8 0 R >> >> >>",
		streamObj("BT /F1 12 Tf (\001) Tj ET"),
		"<< /Type /Font /Subtype /Type1 /ToUnicode 10 0 R >>",
		"<< /Type /Font /Subtype /Type1 /ToUnicode 11 0 R >>",
		cmap("0058"), cmap("0059"), cmap("005a"),
	))
	rd, err := r.GetPlainText()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	b.ReadFrom(rd)
	if got := b.String(); got != "\nX\nY\nZ" {
		t.Errorf("GetPlainText = %q, want %q", got, "\nX\nY\nZ")
	}
}

// TestFontsParsedOncePerReader verifies that pages sharing a font object
// share its parsed widths.
func TestFontsParsedOncePerReader(t *testing.T) {
	const pages = 100
	w := "[0 [" + strings.Repeat("500 ", maxCIDWidths) + "]]"
	var kids strings.Builder
	objs := []string{
		"<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /DescendantFonts [4 0 R] >>",
		"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /X /W " + w + " >>",
		flateObj("BT /F1 12 Tf <00010002> Tj ET"),
	}
	for i := range pages {
		fmt.Fprintf(&kids, "%d 0 R ", 6+i)
		objs = append(objs, "<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>")
	}
	root := fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d /Resources << /Font << /F1 3 0 R >> >> >>", kids.String(), pages)
	r := openPDF(t, pageTreePDF(root, objs...))
	first := allocated(func() { r.Page(1).Content() })
	rest := allocated(func() {
		for i := 2; i <= pages; i++ {
			// Each two-byte code decodes to two runes sharing its width.
			if got := r.Page(i).Content().Text; len(got) != 4 || got[2].X-got[0].X != 6 {
				t.Fatalf("page %d texts %v, want two codes 6 apart", i, got)
			}
		}
	})
	if rest > first {
		t.Errorf("pages 2 to %d allocated %d KB, page 1 %d KB", pages, rest>>10, first>>10)
	}
}
