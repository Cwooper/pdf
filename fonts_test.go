package pdf

import (
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
