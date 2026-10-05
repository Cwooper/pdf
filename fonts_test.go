package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"
)

// flateObj returns a Flate-compressed stream object holding content.
func flateObj(content string) string {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write([]byte(content))
	w.Close()
	return fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream", z.Len(), z.String())
}

// fontPage returns a one-page reader whose page shows content with font
// /F1, the font dictionary given, and extra objects numbered from 6.
func fontPage(t *testing.T, content, font string, extra ...string) *Reader {
	t.Helper()
	data := buildPDF(append([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		flateObj(content),
		font,
	}, extra...)...)
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestCmapDestinationCap verifies that a ToUnicode destination longer than
// the 512 bytes the CMap format allows is not kept: one code expanding to a
// megabyte, shown a few thousand times, ran 1.2 KB out of memory.
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
		return func() {
			defer func() {
				if recover() == nil {
					t.Error("Content returned, want the glyph cap reported")
				}
			}()
			p.Content()
		}
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
