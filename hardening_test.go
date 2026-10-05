// Follow-up hardening on top of the absorbed upstream PR #78: cases its
// review surfaced. Each case was verified to hang, panic or misbehave before
// the corresponding fix.

package pdf

import (
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
)

// TestSparseXrefIndexAllocation verifies that naming a far-off object number
// costs memory in proportion to the entries actually read, not to the number.
// A file of a couple hundred bytes used to allocate 256 MB here.
func TestSparseXrefIndexAllocation(t *testing.T) {
	data := xrefStreamPDF("/Size 1 /W [1 1 1] /Index [2147483648 1]", "\x01\x09\x00")

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := NewReader(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 8<<20 {
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
	data := []byte(b.String())

	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
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
// cross-reference table treats every reference as unresolvable, as it did
// when the table was a nil slice.
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
// forever. Both the classic-table and xref-stream paths had the loop.
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

// TestCyclicOutlineCombined verifies that an outline whose /First and /Next
// both point back at the same entry terminates. The per-axis caps (depth and
// siblings) composed combinatorially: each of up to 65536 siblings recursed
// into up to 128 levels, ~65536^128 visits.
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
	data := []byte(b.String())

	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
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
	data := xrefTablePDF(
		"0 2\n0000000000 65535 f \n0009999999 00000 n \n",
		"<< /Size 2 /Root << /Outlines << /First 1 0 R >> >> >>",
	)
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	mustNotCrash(t, func() { r.Outline() })
}

// TestObjectStreamHeaderCycle verifies that a cycle through an object
// stream's own header terminates: /N is a reference to an object the stream
// claims to contain, so resolving it re-entered the stream until the
// goroutine stack overflowed, which is fatal rather than recoverable.
func TestObjectStreamHeaderCycle(t *testing.T) {
	data := buildObjStmPDF("/N 7 0 R /First FIRST", "", 1)
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
// odd digit count behaves as if a final 0 were appended. <F> used to panic in
// readHexString because the terminator was read as the second hex digit.
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
// to zero is rejected. With no bytes per entry the entry loop consumed no
// input, so a 207-byte file ran 8 million iterations and grew the table to
// over a gigabyte.
func TestXrefStreamZeroWidths(t *testing.T) {
	data := xrefStreamPDF("/Size 8388608 /W [0 0 0]", "")
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := openBytes(data)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Error("NewReader: got nil error, want the zero-width /W rejected")
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 8<<20 {
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
// being opened still discards the cmap, as it always did: with no codespace
// ranges at all a cmap maps every byte to the replacement character, so
// falling back to raw bytes reads better.
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

// TestNegativeStreamLength verifies that a negative /Length yields an empty
// stream. io.NewSectionReader treats a negative length as unbounded, so the
// stream used to run to the end of the file.
func TestNegativeStreamLength(t *testing.T) {
	const file = "stream body and everything after it"
	r := &Reader{f: bytes.NewReader([]byte(file)), end: int64(len(file))}
	v := Value{r: r, data: stream{dict{name("Length"): int64(-1)}, objptr{}, 0}}
	got, err := io.ReadAll(v.Reader())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("read %d bytes from a stream with /Length -1, want 0", len(got))
	}
}

// TestObjectStreamJunkPairSkipped verifies that a malformed entry in an object
// stream's index table is skipped rather than ending the scan, so the objects
// listed after it still resolve.
func TestObjectStreamJunkPairSkipped(t *testing.T) {
	data := buildObjStmPDF("/N 4 /First FIRST", "9 12.0 ", 0)
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	text, err := r.GetPlainText()
	if err != nil {
		t.Fatalf("GetPlainText: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(text)
	if !strings.Contains(buf.String(), "Hello Stream") {
		t.Errorf("GetPlainText = %q, want it to contain %q", buf.String(), "Hello Stream")
	}
}

// TestObjectStreamIndexJunkValues verifies two more kinds of junk in an
// object stream index that must not stop objects listed after them from
// resolving: a negative offset in a pair that is not being looked up, and an
// object number outside the 32-bit range, which used to alias a real one.
func TestObjectStreamIndexJunkValues(t *testing.T) {
	for _, prefix := range []string{"9 -1 ", "4294967297 5 ", "-4294967295 5 "} {
		t.Run(strings.TrimSpace(prefix), func(t *testing.T) {
			data := buildObjStmPDF("/N 4 /First FIRST", prefix, 0)
			r, err := NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatalf("NewReader: %v", err)
			}
			text, err := r.GetPlainText()
			if err != nil {
				t.Fatalf("GetPlainText: %v", err)
			}
			var buf bytes.Buffer
			buf.ReadFrom(text)
			if !strings.Contains(buf.String(), "Hello Stream") {
				t.Errorf("GetPlainText = %q, want it to contain %q", buf.String(), "Hello Stream")
			}
		})
	}
}

// noRuntimePanic fails if fn panics with a runtime error. Page and NumPage
// report malformed input by panicking, so other panics are expected.
func noRuntimePanic(t *testing.T, fn func()) {
	t.Helper()
	p, timedOut := run(t, fn)
	if timedOut {
		t.Errorf("did not return within %v", caseTimeout)
	}
	if _, ok := p.(runtime.Error); ok {
		t.Errorf("runtime panic: %v", p)
	}
}

// TestNegativeOffsets verifies that negative offsets in the xref table or in
// an object stream, and an object stream entry that points back before the
// window its index table has already read past, are reported as malformed
// input rather than indexing a buffer out of range.
func TestNegativeOffsets(t *testing.T) {
	negXref := buildPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
	)
	i := bytes.Index(negXref, []byte(" 65535 f \n")) + len(" 65535 f \n")
	copy(negXref[i:], "-000000001")

	tests := []struct {
		name string
		data []byte
	}{
		{"xref offset", negXref},
		{"xref stream offset", xrefStreamPDF("/Size 2 /W [1 8 0] /Index [1 1] /Root 1 0 R", "\x01"+strings.Repeat("\xff", 8))},
		{"object stream First", objStmPDFWith("/N 3 /First -100000")},
		{"object stream seek back", buildObjStmPDF("/N 1103 /First 1", strings.Repeat("9 0 ", 1100), 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewReader(bytes.NewReader(tt.data), int64(len(tt.data)))
			if err != nil {
				return
			}
			noRuntimePanic(t, func() { r.NumPage() })
			noRuntimePanic(t, func() { r.Page(1) })
		})
	}
}

// TestNegativeXrefStart verifies that a negative startxref or /Prev is
// reported as malformed input rather than slicing the lexer's buffer out of
// range.
func TestNegativeXrefStart(t *testing.T) {
	for name, data := range map[string][]byte{
		"startxref":   []byte("%PDF-1.4\n" + pad() + "startxref\n-1\n%%EOF\n"),
		"table Prev":  xrefTablePDF("0 1\n0000000000 65535 f \n", "<< /Size 1 /Prev -1 >>"),
		"stream Prev": xrefStreamPDF("/Size 1 /W [1 1 1] /Prev -1", "\x00\x00\x00"),
	} {
		if err := openBytes(data); err == nil || strings.Contains(err.Error(), "runtime error") {
			t.Errorf("%s: got %v, want it reported as malformed", name, err)
		}
	}
}

// buildPDF returns a file holding objs as objects 1, 2, ..., with object 1
// as the catalog.
func buildPDF(objs ...string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offs := make([]int, len(objs))
	for i, o := range objs {
		offs[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

// TestXrefTableAtEntryCap verifies that a compressed xref stream describing
// more entries than the table may hold is refused within a modest
// allocation. 24 KB describing eight million entries grew the table past a
// gigabyte.
func TestXrefTableAtEntryCap(t *testing.T) {
	const rows = 1 << 23
	var comp bytes.Buffer
	zw := zlib.NewWriter(&comp)
	zw.Write(bytes.Repeat([]byte{1, 9, 0}, rows))
	zw.Close()
	data := xrefStreamPDF(fmt.Sprintf("/Size %d /W [1 1 1] /Filter /FlateDecode", rows), comp.String())

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := openBytes(data)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Errorf("NewReader: got nil error, want the entry bound reported")
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 128<<20 {
		t.Errorf("opening a %d-byte file allocated %d MB", len(data), got>>20)
	}
}

// TestXrefRowsBounded verifies that the rows an xref stream chain is scanned
// for count against one budget, of exactly maxXrefRows, whether or not they
// are stored. Rows of an unknown type, or for objects a later section already
// describes, were never counted, so a 99 KB file spent 55 seconds scanning
// them.
func TestXrefRowsBounded(t *testing.T) {
	chain := func(rows int) []byte {
		var comp bytes.Buffer
		zw := zlib.NewWriter(&comp)
		zw.Write(bytes.Repeat([]byte{3, 0}, rows))
		zw.Close()
		section := func(num int, extra string) string {
			return fmt.Sprintf("%d 0 obj\n<< /Type /XRef /Size %d /W [1 1 0] /Filter /FlateDecode /Length %d %s >>\nstream\n%s\nendstream\nendobj\n",
				num, rows, comp.Len(), extra, comp.String())
		}

		var b strings.Builder
		b.WriteString("%PDF-1.5\n")
		b.WriteString(pad())
		prev := b.Len()
		b.WriteString(section(1, ""))
		start := b.Len()
		b.WriteString(section(2, fmt.Sprintf("/Prev %d", prev)))
		fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", start)
		return []byte(b.String())
	}

	if err := openBytes(chain(maxXrefRows / 2)); err != nil {
		t.Errorf("%d rows: NewReader: %v", maxXrefRows, err)
	}
	if err := openBytes(chain(maxXrefRows/2 + 1)); err == nil || !strings.Contains(err.Error(), "rows") {
		t.Errorf("%d rows: got %v, want the row budget reported", maxXrefRows+2, err)
	}
}

// TestObjectStreamByteCap verifies that an object stream may decode to
// exactly maxObjStmBytes, and that resolving an object placed further in is
// refused rather than inflating the whole gap: 17 KB of nested Flate put an
// object 4 GiB in, and every resolve took ten seconds.
func TestObjectStreamByteCap(t *testing.T) {
	const catalog = "<< /Type /Catalog /Pages << /Type /Pages /Kids [] /Count 7 >> >>"
	// open returns a file whose object stream decodes to size bytes, the
	// catalog last.
	open := func(size int) *Reader {
		gap := size - len(catalog) - len(fmt.Sprintf("1 %d ", size))
		index := fmt.Sprintf("1 %d ", gap)
		var comp bytes.Buffer
		zw := zlib.NewWriter(&comp)
		zw.Write([]byte(index))
		zw.Write(make([]byte, gap))
		zw.Write([]byte(catalog))
		zw.Close()

		var b strings.Builder
		b.WriteString("%PDF-1.5\n")
		off := b.Len()
		fmt.Fprintf(&b, "2 0 obj\n<< /Type /ObjStm /N 1 /First %d /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream\nendobj\n",
			len(index), comp.Len(), comp.String())
		xref := b.Len()
		rows := []byte{0, 0, 0, 0, 0, 2, 0, 0, 2, 0}
		rows = append(rows, 1, byte(off>>16), byte(off>>8), byte(off), 0)
		rows = append(rows, 1, byte(xref>>16), byte(xref>>8), byte(xref), 0)
		fmt.Fprintf(&b, "3 0 obj\n<< /Type /XRef /Size 4 /W [1 3 1] /Root 1 0 R /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(rows), rows)
		fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xref)
		data := []byte(b.String())

		r, err := NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	r := open(maxObjStmBytes)
	if p, _ := run(t, func() {
		if got := r.NumPage(); got != 7 {
			t.Errorf("NumPage = %d, want 7", got)
		}
	}); p != nil {
		t.Errorf("%d bytes: NumPage panicked: %v", maxObjStmBytes, p)
	}
	r = open(maxObjStmBytes + 1)
	p, _ := run(t, func() { r.NumPage() })
	if p == nil || !strings.Contains(fmt.Sprint(p), "exceeds") {
		t.Errorf("%d bytes: NumPage: got panic %v, want the object stream size cap reported", maxObjStmBytes+1, p)
	}
}

// A testObj is an object for xrefStreamFile: a body, or the members of an
// object stream whose header is hdr with FIRST and NUM filled in, or with in
// set, an entry alone placing the object in object stream in.
type testObj struct {
	num     int
	body    string
	hdr     string
	members []testObj
	in      int
}

// objStmLayout returns the decoded data of an object stream holding members
// and its /First.
func objStmLayout(members []testObj) (string, int) {
	var index, bodies strings.Builder
	for _, m := range members {
		fmt.Fprintf(&index, "%d %d ", m.num, bodies.Len())
		bodies.WriteString(m.body + "\n")
	}
	return index.String() + bodies.String(), index.Len()
}

// xrefStreamFile returns a file holding objs behind an xref stream, with
// object 1 as the catalog. An object stream's data is Flate-compressed.
func xrefStreamFile(objs ...testObj) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n")
	rows := map[int][3]int{0: {0, 0, 65535}}
	size := 0
	for _, o := range objs {
		size = max(size, o.num+1)
		if o.in != 0 {
			rows[o.num] = [3]int{2, o.in, 0}
			continue
		}
		rows[o.num] = [3]int{1, b.Len(), 0}
		if o.members == nil {
			fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", o.num, o.body)
			continue
		}
		data, first := objStmLayout(o.members)
		for i, m := range o.members {
			rows[m.num] = [3]int{2, o.num, i}
			size = max(size, m.num+1)
		}
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		zw.Write([]byte(data))
		zw.Close()
		hdr := strings.NewReplacer("FIRST", fmt.Sprint(first), "NUM", fmt.Sprint(len(o.members))).Replace(o.hdr)
		fmt.Fprintf(&b, "%d 0 obj\n<< /Type /ObjStm %s /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream\nendobj\n", o.num, hdr, z.Len(), z.String())
	}
	rows[size] = [3]int{1, b.Len(), 0}
	var e bytes.Buffer
	for i := range size + 1 {
		r := rows[i]
		e.Write([]byte{byte(r[0]), byte(r[1] >> 24), byte(r[1] >> 16), byte(r[1] >> 8), byte(r[1]), byte(r[2] >> 8), byte(r[2])})
	}
	xref := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n<< /Type /XRef /Size %d /W [1 4 2] /Root 1 0 R /Length %d >>\nstream\n%s\nendstream\nendobj\n", size, size+1, e.Len(), e.String())
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xref)
	return b.Bytes()
}

// TestObjectStreamHeaderFanout verifies that an object stream's header is
// read without following references into other object streams. Each stream
// here takes /N and /First from the next, so every level doubled the
// decoding: 9.6 KB allocated 23.5 GB.
func TestObjectStreamHeaderFanout(t *testing.T) {
	const depth = 16
	levels := make([][]testObj, depth+1)
	levels[0] = []testObj{{num: 1, body: "<< /Type /Catalog /Pages << /Type /Pages /Kids [] /Count 7 >> >>"}}
	for i := 1; i <= depth; i++ {
		_, first := objStmLayout(levels[i-1])
		levels[i] = []testObj{
			{num: 200 + 2*i, body: fmt.Sprint(len(levels[i-1]))},
			{num: 201 + 2*i, body: fmt.Sprint(first)},
		}
	}
	var objs []testObj
	for i, members := range levels {
		hdr := "/N NUM /First FIRST"
		if i < depth {
			hdr = fmt.Sprintf("/N %d 0 R /First %d 0 R", 202+2*i, 203+2*i)
		}
		objs = append(objs, testObj{num: 100 + i, hdr: hdr, members: members})
	}
	data := xrefStreamFile(objs...)

	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	run(t, func() { r.NumPage() })
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 8<<20 {
		t.Errorf("NumPage on a %d-byte file allocated %d MB", len(data), got>>20)
	}
}

// TestObjectStreamIndexCap verifies that object streams may index exactly
// maxXrefEntries objects between them, and not one more.
func TestObjectStreamIndexCap(t *testing.T) {
	data := xrefStreamFile(testObj{num: 2, hdr: "/N NUM /First FIRST", members: []testObj{
		{num: 3, body: "null"},
		{num: 1, body: "<< /Type /Catalog /Pages << /Type /Pages /Kids [] /Count 7 >> >>"},
	}})
	for _, tt := range []struct {
		before int64
		ok     bool
	}{{maxXrefEntries - 2, true}, {maxXrefEntries - 1, false}} {
		r, err := NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		r.cache.indexed.Store(tt.before)
		got := 0
		p, _ := run(t, func() { got = r.NumPage() })
		if tt.ok && (p != nil || got != 7) {
			t.Errorf("%d indexed before: NumPage = %d, panic %v; want 7", tt.before, got, p)
		}
		if !tt.ok && !strings.Contains(fmt.Sprint(p), "index more than") {
			t.Errorf("%d indexed before: got panic %v, want the index cap reported", tt.before, p)
		}
	}
}

// TestObjectStreamExtendsCap verifies that an object found maxObjStmExtends
// streams down an /Extends chain resolves, and one a stream further does not.
func TestObjectStreamExtendsCap(t *testing.T) {
	const catalog = "<< /Type /Catalog /Pages << /Type /Pages /Kids [] /Count 7 >> >>"
	for _, n := range []int{maxObjStmExtends, maxObjStmExtends + 1} {
		var objs []testObj
		for i := range n {
			hdr, member := "/N NUM /First FIRST", testObj{num: 1, body: catalog}
			if i < n-1 {
				hdr += fmt.Sprintf(" /Extends %d 0 R", 101+i)
				member = testObj{num: 200 + i, body: "null"}
			}
			objs = append(objs, testObj{num: 100 + i, hdr: hdr, members: []testObj{member}})
		}
		data := xrefStreamFile(append(objs, testObj{num: 1, in: 100})...)
		r, err := NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		got := 0
		p, _ := run(t, func() { got = r.NumPage() })
		if n == maxObjStmExtends && (p != nil || got != 7) {
			t.Errorf("chain of %d: NumPage = %d, panic %v; want 7", n, got, p)
		}
		if n > maxObjStmExtends && !strings.Contains(fmt.Sprint(p), "too long") {
			t.Errorf("chain of %d: got panic %v, want the chain cap reported", n, p)
		}
	}
}

// TestObjectStreamDecodedOnce verifies that resolving many objects from one
// object stream decodes it once, not once per object: a 23-page paper took
// 3.8 seconds re-inflating its streams.
func TestObjectStreamDecodedOnce(t *testing.T) {
	const pages = 1000
	members := []testObj{
		{num: 3, body: "(" + strings.Repeat("x", 1<<20) + ")"},
		{num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>"},
	}
	var kids strings.Builder
	for i := range pages {
		fmt.Fprintf(&kids, "%d 0 R ", 10+i)
		members = append(members, testObj{num: 10 + i, body: "<< /Type /Page /Parent 2 0 R >>"})
	}
	members = append(members, testObj{num: 2, body: fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), pages)})
	data := xrefStreamFile(testObj{num: 5, hdr: "/N NUM /First FIRST", members: members})

	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	kidsV := r.Trailer().Key("Root").Key("Pages").Key("Kids")
	for i := range kidsV.Len() {
		if got := kidsV.Index(i).Key("Type").Name(); got != "Page" {
			t.Fatalf("kid %d has /Type %q, want Page", i, got)
		}
	}
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 16<<20 {
		t.Errorf("resolving %d objects from one stream allocated %d MB", pages, got>>20)
	}
}

// TestFilterChainCap verifies that a /Filter array of up to maxFilters
// decodes and a longer one is refused before its decoders are built: an
// indirect array of a million filters ran a 29.6 KB file out of 2 GB.
func TestFilterChainCap(t *testing.T) {
	page := func(layers int) Page {
		content := "BT (x) Tj ET"
		for range layers {
			var b bytes.Buffer
			w := ascii85.NewEncoder(&b)
			w.Write([]byte(content))
			w.Close()
			content = b.String() + "~>"
		}
		data := buildPDF(
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
			"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>",
			fmt.Sprintf("<< /Length %d /Filter 5 0 R >>\nstream\n%s\nendstream", len(content), content),
			"["+strings.Repeat("/ASCII85Decode ", layers)+"]",
		)
		r, err := NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		return r.Page(1)
	}
	if got, err := page(maxFilters).GetPlainText(nil); err != nil || got != "\nx" {
		t.Errorf("%d filters: GetPlainText = %q, %v; want %q", maxFilters, got, err, "\nx")
	}
	if _, err := page(maxFilters + 1).GetPlainText(nil); err == nil || !strings.Contains(err.Error(), "filters") {
		t.Errorf("%d filters: got %v, want the filter cap reported", maxFilters+1, err)
	}
}

// TestDecodeBudgetBeneathPredictor verifies that the inflate beneath a
// predictor counts against the budget although the predictor yields
// nothing: with no /Columns every row is the filter byte alone, and 17 KB
// held 4 GiB of them.
func TestDecodeBudgetBeneathPredictor(t *testing.T) {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	row := bytes.Repeat([]byte{2}, 1<<20)
	for range minDecodeBudget>>20 + 1 {
		zw.Write(row)
	}
	zw.Close()
	data := buildPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d /Filter /FlateDecode /DecodeParms << /Predictor 12 >> >>\nstream\n%s\nendstream", z.Len(), z.String()),
	)
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Page(1).GetPlainText(nil); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Errorf("GetPlainText: got %v, want the decode budget reported", err)
	}
}

// TestDecodeBudget verifies that the bytes all of a Reader's streams decode
// to count against one budget. Each page's own caps held, but pages sharing
// one stream that inflates to 64 MiB decoded gigabytes from 70 KB.
func TestDecodeBudget(t *testing.T) {
	const chunk = 8 << 20
	pages := minDecodeBudget/chunk + 1
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(make([]byte, chunk))
	zw.Write([]byte("BT (x) Tj ET"))
	zw.Close()
	objs := []string{"<< /Type /Catalog /Pages 2 0 R >>", "",
		fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream", z.Len(), z.String())}
	var kids strings.Builder
	for i := range pages {
		fmt.Fprintf(&kids, "%d 0 R ", 4+i)
		objs = append(objs, "<< /Type /Page /Parent 2 0 R /Contents 3 0 R >>")
	}
	objs[1] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), pages)
	data := buildPDF(objs...)
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= pages; i++ {
		if _, err = r.Page(i).GetPlainText(nil); err != nil {
			break
		}
	}
	if err == nil || !strings.Contains(err.Error(), "budget") {
		t.Errorf("reading %d pages of %d MB each: got %v, want the decode budget reported", pages, chunk>>20, err)
	}
}

// BenchmarkValueIndex measures the accessor every traversal runs through. A
// field added to Value once made it four times slower.
func BenchmarkValueIndex(b *testing.B) {
	arr := make(array, 256)
	for i := range arr {
		arr[i] = int64(500)
	}
	v := Value{data: arr}
	var sum float64
	for i := 0; b.Loop(); i++ {
		sum += v.Index(i & 255).Float64()
	}
	_ = sum
}
