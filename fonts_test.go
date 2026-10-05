package pdf

import (
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
