package pdf

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// TestSparseXrefIndexAllocation verifies that naming a far-off object number
// costs memory in proportion to the entries actually read, not to the number.
func TestSparseXrefIndexAllocation(t *testing.T) {
	data := xrefStreamPDF("/Size 1 /W [1 1 1] /Index [2147483648 1]", "\x01\x09\x00")
	if got := allocated(func() { openPDF(t, data) }); got > 8<<20 {
		t.Errorf("opening a %d-byte file allocated %d MB", len(data), got>>20)
	}
}

// TestSparseObjectNumberResolves verifies that an object numbered far past
// its neighbours, which the table keeps outside the dense slice, still
// resolves.
func TestSparseObjectNumberResolves(t *testing.T) {
	var b strings.Builder
	b.WriteString("%PDF-1.4\n")
	b.WriteString(pad())
	objOff := b.Len()
	b.WriteString("500000 0 obj\n<< /Type /Catalog /Pages << /Type /Pages /Kids [] /Count 3 >> >>\nendobj\n")
	xrefOff := b.Len()
	fmt.Fprintf(&b, "xref\n0 1\n0000000000 65535 f \n500000 1\n%010d 00000 n \n", objOff)
	b.WriteString("trailer\n<< /Size 500001 /Root 500000 0 R >>\n")
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xrefOff)
	r := openPDF(t, []byte(b.String()))
	if got := r.NumPage(); got != 3 {
		t.Errorf("NumPage = %d, want 3 (catalog at object 500000 not resolved)", got)
	}
}

// TestXrefTableDenseGrowthKeepsSparse verifies that an entry stored sparse,
// because its number was far past the table at the time, is still found after
// the dense slice grows across it.
func TestXrefTableDenseGrowthKeepsSparse(t *testing.T) {
	const far = 200000
	table := newXrefTable(0)
	table.put(far, xref{ptr: objptr{far, 0}, offset: 99})
	for i := 0; i < 70000; i++ {
		table.put(i, xref{ptr: objptr{uint32(i), 0}, offset: 9})
	}
	table.put(far+1, xref{ptr: objptr{far + 1, 0}, offset: 9})
	if got := table.get(far); got.offset != 99 {
		t.Errorf("get(%d) = %+v, want the entry stored before the dense slice grew past it", far, got)
	}
}

// TestResolveWithoutXref verifies that a Reader that never loaded a
// cross-reference table treats every reference as unresolvable.
func TestResolveWithoutXref(t *testing.T) {
	r := &Reader{f: bytes.NewReader(nil), end: 0}
	mustNotCrash(t, func() {
		if v := r.resolve(objptr{}, objptr{1, 0}); !v.IsNull() {
			t.Errorf("resolved %v from an empty reader", v)
		}
	})
}

// TestXrefEntryBound verifies that a table already holding maxXrefEntries
// refuses another entry on both the classic and the xref stream path.
func TestXrefEntryBound(t *testing.T) {
	full := func() *xrefTable {
		table := newXrefTable(0)
		table.n = maxXrefEntries
		return table
	}

	b := newBuffer(strings.NewReader("1 1\n0000000009 00000 n \ntrailer"), 0)
	if _, err := readXrefTableData(b, full()); err == nil {
		t.Error("classic table: got nil error, want the entry bound reported")
	}

	data := "\x01\x09\x00"
	r := &Reader{f: bytes.NewReader([]byte(data)), end: int64(len(data))}
	hdr := dict{name("Length"): int64(len(data)), name("W"): array{int64(1), int64(1), int64(1)}, name("Index"): array{int64(1), int64(1)}}
	if _, err := readXrefStreamData(r, stream{hdr, objptr{}, 0}, full(), 2); err == nil {
		t.Error("xref stream: got nil error, want the entry bound reported")
	}
}

// TestCyclicPrevChain verifies that a cross-reference /Prev pointing back at
// an already-visited offset terminates instead of re-reading the same section
// forever.
func TestCyclicPrevChain(t *testing.T) {
	headerLen := len("%PDF-1.4\n" + pad())

	t.Run("classic table", func(t *testing.T) {
		data := xrefTablePDF(
			"0 1\n0000000000 65535 f \n",
			fmt.Sprintf("<< /Size 1 /Prev %d >>", headerLen),
		)
		mustNotCrash(t, func() { openBytes(data) })
	})

	t.Run("xref stream", func(t *testing.T) {
		data := xrefStreamPDF(
			fmt.Sprintf("/Size 1 /W [1 1 1] /Prev %d", headerLen),
			"\x01\x09\x00",
		)
		mustNotCrash(t, func() { openBytes(data) })
	})
}

// TestCyclicOutlineCombined verifies that an outline entry whose /First and
// /Next both hold the entry itself, a direct cycle seen cannot catch,
// terminates.
func TestCyclicOutlineCombined(t *testing.T) {
	d := dict{name("Title"): "t"}
	d[name("First")] = d
	d[name("Next")] = d
	r := &Reader{f: bytes.NewReader(nil), end: 0}
	r.trailer = dict{name("Root"): dict{name("Outlines"): d}}
	mustNotCrash(t, func() { r.Outline() })
}

// TestCyclicOutlineByReference verifies that an outline entry reached through
// an object reference is visited once. The node budget stops a cycle
// eventually, but a cycle of a single entry with a long title would otherwise
// be copied out tens of thousands of times.
func TestCyclicOutlineByReference(t *testing.T) {
	var b strings.Builder
	b.WriteString("%PDF-1.4\n")
	b.WriteString(pad())
	objOff := b.Len()
	b.WriteString("1 0 obj\n<< /Title (loop) /First 1 0 R /Next 1 0 R >>\nendobj\n")
	xrefOff := b.Len()
	fmt.Fprintf(&b, "xref\n0 2\n0000000000 65535 f \n%010d 00000 n \n", objOff)
	b.WriteString("trailer\n<< /Size 2 /Root << /Outlines << /First 1 0 R >> >> >>\n")
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xrefOff)
	r := openPDF(t, []byte(b.String()))
	if n := countOutline(r.Outline()); n > 3 {
		t.Errorf("outline has %d nodes, want the single entry visited once", n)
	}
}

func countOutline(o Outline) int {
	n := 1
	for _, c := range o.Child {
		n += countOutline(c)
	}
	return n
}

// TestOutlineMalformedReturns verifies that Outline, which has no error
// return, absorbs the panic resolve raises on a broken reference rather than
// letting it reach the caller.
func TestOutlineMalformedReturns(t *testing.T) {
	r := openPDF(t, xrefTablePDF(
		"0 2\n0000000000 65535 f \n0009999999 00000 n \n",
		"<< /Size 2 /Root << /Outlines << /First 1 0 R >> >> >>",
	))
	mustNotCrash(t, func() { r.Outline() })
}

// TestObjectStreamHeaderCycle verifies the resolve depth cap holds when the
// cycle runs through an object stream's own header: /N is a reference to an
// object the stream claims to contain, so resolving it re-enters the stream.
// Before the fix the depth counter restarted at zero on each hop and the
// goroutine stack overflowed, which is fatal rather than recoverable.
func TestObjectStreamHeaderCycle(t *testing.T) {
	data := buildObjStmPDF("/N 7 0 R /First FIRST", 1)
	mustNotCrash(t, func() {
		r, err := NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		if _, err := r.GetPlainText(); err == nil {
			t.Error("GetPlainText: got nil error, want the cycle reported")
		}
	})
}

// TestOddLengthHexString verifies the PDF 7.3.4.3 rule: a hex string with an
// odd digit count behaves as if a final 0 were appended.
func TestOddLengthHexString(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"<F>", "\xf0"},
		{"<ABC>", "\xab\xc0"},
		{"<901FA>", "\x90\x1f\xa0"},
		{"<90 1F A>", "\x90\x1f\xa0"},
	} {
		var tok token
		mustNotCrash(t, func() {
			b := newBuffer(strings.NewReader(tc.in), 0)
			b.allowEOF = true
			tok = b.readToken()
		})
		if got, ok := tok.(string); !ok || got != tc.want {
			t.Errorf("%q: token = %#v, want %q", tc.in, tok, tc.want)
		}
	}
}

// TestXrefStreamZeroWidths verifies that an xref stream whose /W widths sum
// to zero, so that its entries consume no input, is rejected.
func TestXrefStreamZeroWidths(t *testing.T) {
	data := xrefStreamPDF("/Size 8388608 /W [0 0 0]", "")
	var err error
	got := allocated(func() { err = openBytes(data) })
	if err == nil {
		t.Error("NewReader: got nil error, want the zero-width /W rejected")
	}
	if got > 8<<20 {
		t.Errorf("opening a %d-byte file allocated %d MB", len(data), got>>20)
	}
}

// TestHugePageCount verifies that a /Count far beyond the pages the tree
// holds does not turn text extraction into a loop over every claimed number.
func TestHugePageCount(t *testing.T) {
	r := &Reader{f: bytes.NewReader(nil), end: 0}
	r.trailer = dict{name("Root"): dict{name("Pages"): dict{
		name("Type"): name("Pages"), name("Kids"): array{}, name("Count"): int64(1 << 40),
	}}}
	mustNotCrash(t, func() {
		r.GetPlainText()
		r.GetStyledTexts()
	})
}

// TestCmapCountMismatchSalvaged verifies that a block whose declared count
// exceeds the pairs present keeps the pairs that are there. Generators
// miscount these blocks often enough that discarding the whole cmap turns
// readable text into raw codes.
func TestCmapCountMismatchSalvaged(t *testing.T) {
	const space = "1 begincodespacerange <00> <ff> endcodespacerange "

	tests := []struct {
		name    string
		content string
		in, out string
	}{
		{"bfchar over", space + "3 beginbfchar <41> <0061> <42> <0062> endbfchar", "A", "a"},
		{"bfrange over", space + "2 beginbfrange <43> <45> <0063> endbfrange", "D", "d"},
		{"codespace over", "2 begincodespacerange <00> <ff> endcodespacerange 1 beginbfchar <41> <0061> endbfchar", "A", "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := readCmap(rawStream(tt.content))
			if m == nil {
				t.Fatal("readCmap returned nil, want the salvaged mappings")
			}
			if got := m.Decode(tt.in); got != tt.out {
				t.Errorf("Decode(%q) = %q, want %q", tt.in, got, tt.out)
			}
		})
	}
}

// TestCmapMissingBeginDiscarded verifies that a block closed without ever
// being opened discards the cmap: with no codespace ranges at all a cmap maps
// every byte to the replacement character, so falling back to raw bytes reads
// better.
func TestCmapMissingBeginDiscarded(t *testing.T) {
	for _, content := range []string{
		"endcodespacerange 1 beginbfchar <41> <0061> endbfchar",
		"1 begincodespacerange <00> <ff> endcodespacerange endbfchar",
		"1 begincodespacerange <00> <ff> endcodespacerange endbfrange",
	} {
		if m := readCmap(rawStream(content)); m != nil {
			t.Errorf("readCmap(%q) = %v, want nil", content, m)
		}
	}
}

// TestToUnicodeStreamErrorReported verifies that a ToUnicode stream that
// cannot be read at all -- an unsupported filter here -- is reported like any
// other unreadable stream, rather than silently decoding text with no cmap.
func TestToUnicodeStreamErrorReported(t *testing.T) {
	const content = "BT /F1 12 Tf (AB) Tj ET"
	file := content + "junk"
	r := &Reader{f: bytes.NewReader([]byte(file)), end: int64(len(file))}
	toUnicode := stream{dict{name("Length"): int64(4), name("Filter"): name("LZWDecode")}, objptr{}, int64(len(content))}
	font := dict{name("Type"): name("Font"), name("Subtype"): name("Type1"), name("ToUnicode"): toUnicode}
	page := dict{
		name("Resources"): dict{name("Font"): dict{name("F1"): font}},
		name("Contents"):  stream{dict{name("Length"): int64(len(content))}, objptr{}, 0},
	}
	p := Page{V: Value{r: r, data: page}}
	if _, err := p.GetPlainText(nil); err == nil {
		t.Error("GetPlainText: got nil error, want the unsupported ToUnicode filter reported")
	}
}

// TestDeepPageTreeInheritsResources verifies that a page as deep as the page
// tree walk allows still inherits attributes from the top of the tree: Page
// descends maxPageTreeDepth levels, so the page has that many ancestors.
func TestDeepPageTreeInheritsResources(t *testing.T) {
	root := dict{name("Resources"): dict{name("Font"): dict{name("F1"): dict{}}}}
	cur := root
	for i := 0; i < maxPageTreeDepth-1; i++ {
		cur = dict{name("Parent"): cur}
	}
	page := dict{name("Type"): name("Page"), name("Parent"): cur}
	r := &Reader{f: bytes.NewReader(nil), end: 0}
	p := Page{V: Value{r: r, data: page}}
	if got := p.Fonts(); len(got) != 1 || got[0] != "F1" {
		t.Errorf("Fonts = %v, want [F1]", got)
	}
}
