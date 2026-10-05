package pdf

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// Each target below feeds one parser input a whole-file mutation rarely
// reaches intact: bytes inside a stream behind a valid xref, or plaintext
// behind a filter or a cipher.

// tolerate runs fn, letting through the panics the package raises by design
// for malformed input and failing on any runtime error.
func tolerate(fn func()) {
	defer func() {
		if x := recover(); x != nil {
			if _, ok := x.(runtime.Error); ok {
				panic(x)
			}
		}
	}()
	fn()
}

// checkErr fails if err is a runtime panic that an API recovered into an
// error.
func checkErr(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "runtime error") {
		t.Fatalf("%s: %v", what, err)
	}
}

// fuzzKeys are the file keys FuzzLex and FuzzStream decrypt with, chosen by
// a mode byte: none, 40-bit RC4, 128-bit RC4, and AES.
var fuzzKeys = []struct {
	key    []byte
	useAES bool
}{{nil, false}, {[]byte("40bit"), false}, {[]byte(testID), false}, {[]byte(testID), true}}

// objSize returns the string bytes and the array and dict entries x holds.
func objSize(x object) (strs, entries int) {
	switch x := x.(type) {
	case string:
		return len(x), 0
	case array:
		for _, e := range x {
			s, n := objSize(e)
			strs, entries = strs+s, entries+n+1
		}
	case dict:
		for _, e := range x {
			s, n := objSize(e)
			strs, entries = strs+s, entries+n+1
		}
	case stream:
		return objSize(x.hdr)
	case objdef:
		return objSize(x.obj)
	}
	return strs, entries
}

// FuzzLex reads objects from raw bytes until the end of input, decrypting
// strings inside an object definition when the mode selects a key.
func FuzzLex(f *testing.F) {
	f.Add([]byte("1 0 obj <</A [1 2 (x\\)) <414>] /B 2 0 R /C -.5 /D#20E true>> endobj"), byte(0))
	f.Add([]byte("<</Length 3>>stream\nabc\nendstream [null false 1.5 (a(b)c\\101\\n) <a b>]"), byte(0))
	f.Add([]byte("7 0 obj [(0123456789abcdef0123456789abcdef) <00112233445566778899aabbccddeeff>] endobj"), byte(4))
	f.Add([]byte("7 0 obj [(0123456789abcdef0123456789abcdef) <00112233445566778899aabbccddeeff>] endobj"), byte(12))
	f.Add([]byte("[[[<<% comment\n/K [ 1 0 R ] >>]]] 3 0 obj 4 0 obj null endobj endobj"), byte(1))
	f.Fuzz(func(t *testing.T, data []byte, mode byte) {
		b := newBuffer(bytes.NewReader(data), 0)
		b.allowEOF = true
		b.allowObjptr = mode&1 == 0
		b.allowStream = mode&2 == 0
		k := fuzzKeys[int(mode>>2)%len(fuzzKeys)]
		b.key, b.useAES = k.key, k.useAES
		var strs, entries int
		// Every object but the last consumes a token, at least a byte.
		for n := 0; ; n++ {
			if n > len(data)+1 {
				t.Fatalf("%d objects from %d bytes", n, len(data))
			}
			var obj object
			tolerate(func() { obj = b.readObject() })
			if obj == io.EOF {
				break
			}
			s, e := objSize(obj)
			strs, entries = strs+s, entries+e
		}
		if strs > len(data) || entries > len(data) {
			t.Fatalf("%d string bytes and %d entries from %d bytes", strs, entries, len(data))
		}
	})
}

// xrefFuzzFile returns a file whose xref stream holds rows, Flate-compressed
// if flate is set, under the header entries hdr, and the offsets of its
// objects 1 to 3.
func xrefFuzzFile(hdr string, rows []byte, flate bool) ([]byte, [4]int) {
	var b bytes.Buffer
	var offs [4]int
	b.WriteString("%PDF-1.5\n")
	offs[1] = b.Len()
	b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	offs[2] = b.Len()
	b.WriteString("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")
	offs[3] = b.Len()
	filter := ""
	if flate {
		rows, filter = deflate(rows), "/Filter /FlateDecode"
	}
	fmt.Fprintf(&b, "3 0 obj\n<< /Type /XRef /Size 4 /Root 1 0 R /Length %d %s %s >>\nstream\n%s\nendstream\nendobj\n", len(rows), filter, hdr, rows)
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", offs[3])
	return b.Bytes(), offs
}

// pngUp encodes data as PNG Up predictor rows of cols bytes.
func pngUp(data []byte, cols int) []byte {
	var out []byte
	prev := make([]byte, cols)
	for len(data) > 0 {
		row := make([]byte, cols)
		data = data[copy(row, data):]
		out = append(out, 2)
		for i := range row {
			out = append(out, row[i]-prev[i])
		}
		prev = row
	}
	return out
}

// FuzzXrefStream opens a file through an xref stream with fuzzed header
// entries (/W, /Index, /Size, /Prev, filters) and rows, then resolves the
// objects it describes.
func FuzzXrefStream(f *testing.F) {
	_, offs := xrefFuzzFile("", nil, false)
	var rows []byte
	for i, off := range offs {
		if i == 0 {
			rows = append(rows, 0, 0, 0, 0, 0xff, 0xff)
			continue
		}
		rows = append(rows, 1, 0, byte(off>>8), byte(off), 0, 0)
	}
	f.Add([]byte("/W [1 3 2]"), rows, false)
	f.Add([]byte("/W [1 3 2] /Index [0 2 2 2]"), rows, true)
	f.Add([]byte("/W [1 3 2] /DecodeParms << /Predictor 12 /Columns 6 >>"), pngUp(rows, 6), true)
	f.Add([]byte("/W [1 3 2] /Index [1 3] /Size 9"), rows[6:], false)
	f.Add([]byte(fmt.Sprintf("/W [1 3 2] /Prev %d", offs[3])), rows, false)
	f.Fuzz(func(t *testing.T, hdr, rows []byte, flate bool) {
		data, _ := xrefFuzzFile(string(hdr), rows, flate)
		r, err := NewReader(bytes.NewReader(data), int64(len(data)))
		checkErr(t, "NewReader", err)
		if err != nil {
			return
		}
		x := r.xref
		if x.n > maxXrefEntries || x.rows > maxXrefRows || len(x.sparse) > x.n || cap(x.dense) > 2*x.n+maxXrefPrealloc {
			t.Fatalf("table holds %d entries from %d rows in %d dense and %d sparse slots", x.n, x.rows, cap(x.dense), len(x.sparse))
		}
		for id := range min(len(x.dense), 64) {
			tolerate(func() { r.resolve(objptr{}, x.dense[id].ptr) })
		}
		tolerate(func() { r.NumPage() })
	})
}

// objStmFuzzFile returns a file whose objects 1 to 8 lie in object stream
// 9, which holds data, Flate-compressed if flate is set, under the header
// entries hdr.
func objStmFuzzFile(hdr string, data []byte, flate bool) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n")
	off := b.Len()
	filter := ""
	if flate {
		data, filter = deflate(data), "/Filter /FlateDecode"
	}
	fmt.Fprintf(&b, "9 0 obj\n<< /Type /ObjStm /Length %d %s %s >>\nstream\n%s\nendstream\nendobj\n", len(data), filter, hdr, data)
	rows := []byte{0, 0, 0, 0, 0xff, 0xff}
	for i := range 8 {
		rows = append(rows, 2, 0, 0, 9, 0, byte(i))
	}
	xref := b.Len()
	rows = append(rows, 1, byte(off>>16), byte(off>>8), byte(off), 0, 0, 1, byte(xref>>16), byte(xref>>8), byte(xref), 0, 0)
	fmt.Fprintf(&b, "10 0 obj\n<< /Type /XRef /Size 11 /W [1 3 2] /Root 1 0 R /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(rows), rows)
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xref)
	return b.Bytes()
}

// FuzzObjStm resolves the objects of one object stream from a fuzzed header,
// index, and body.
func FuzzObjStm(f *testing.F) {
	members := []testObj{
		{num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>"},
		{num: 2, body: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{num: 3, body: "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>"},
		{num: 4, body: "[(abc) 5 0 R]"},
		{num: 5, body: "<< /Next 6 0 R >>"},
		{num: 6, body: "6"},
	}
	data, first := objStmLayout(members)
	hdr := fmt.Sprintf("/N %d /First %d", len(members), first)
	f.Add([]byte(hdr), []byte(data), false)
	f.Add([]byte(hdr), []byte(data), true)
	f.Add([]byte(hdr+" /Extends 9 0 R"), []byte(data[:first]+"7 0 8 3 "+data[first:]), false)
	f.Fuzz(func(t *testing.T, hdr, data []byte, flate bool) {
		file := objStmFuzzFile(string(hdr), data, flate)
		r := openPDF(t, file)
		for id := range uint32(9) {
			tolerate(func() {
				v := r.resolve(objptr{}, objptr{id, 0})
				for _, k := range v.Keys() {
					v.Key(k)
				}
				for i := range min(v.Len(), 8) {
					v.Index(i)
				}
			})
		}
		tolerate(func() { r.NumPage() })
		for _, e := range r.cache.objStms {
			if s := e.v; s != nil && (len(s.data) > maxObjStmBytes || len(s.offs) > int(r.cache.indexed.Load())) {
				t.Fatalf("object stream holds %d bytes and %d offsets", len(s.data), len(s.offs))
			}
		}
	})
}

// FuzzStream reads a stream through Value.Reader with a fuzzed stream
// dictionary, its data compressed and encrypted per the mode so that the
// fuzzed bytes reach the filters past the inflate and the cipher.
func FuzzStream(f *testing.F) {
	f.Add([]byte(""), []byte("BT (Hello) Tj ET"), byte(0))
	f.Add([]byte(""), []byte("BT (Hello) Tj ET"), byte(1))
	f.Add([]byte("/DecodeParms << /Predictor 12 /Columns 4 >>"), pngUp([]byte("BT (Hello) Tj ET"), 4), byte(1))
	f.Add([]byte("/Filter /ASCII85Decode"), []byte("<~87cURD]i,\"Ebo80~>"), byte(0))
	f.Add([]byte("/Filter [/ASCII85Decode /FlateDecode]"), []byte("<~GhQ%0z!!~>"), byte(0))
	f.Add([]byte("/Title (0123456789abcdef0123456789abcdef)"), []byte("BT (Hello) Tj ET"), byte(1|2<<1))
	f.Add([]byte(""), []byte("BT (Hello) Tj ET"), byte(1|3<<1))
	f.Add([]byte("/Length 20"), []byte("BT (Hello) Tj ET"), byte(3<<1))
	f.Add([]byte("/Type /Metadata"), []byte("<x:xmpmeta/>"), byte(1<<1|1<<3))
	f.Fuzz(func(t *testing.T, dict, data []byte, mode byte) {
		k := fuzzKeys[int(mode>>1)%len(fuzzKeys)]
		filter := ""
		if mode&1 != 0 {
			data, filter = deflate(data), "/Filter /FlateDecode"
		}
		if k.key != nil {
			v := 2
			if k.useAES {
				v = 4
			}
			data = cryptSpec{V: v}.encrypt(k.key, 2, data)
		}
		file := buildPDF("<< /Type /Catalog >>", fmt.Sprintf("<< /Length %d %s %s >>\nstream\n%s\nendstream", len(data), filter, dict, data))
		r := openPDF(t, file)
		r.key, r.useAES, r.clearMetadata = k.key, k.useAES, mode&8 != 0
		tolerate(func() {
			n, _ := io.Copy(io.Discard, r.resolve(objptr{}, objptr{2, 0}).Reader())
			if n > r.cache.limit {
				t.Fatalf("stream decoded %d bytes, over the %d-byte budget", n, r.cache.limit)
			}
		})
	})
}

// FuzzPageText extracts a page's text through Content, GetPlainText, and
// GetTextByRow from fuzzed content shown with a fuzzed font /F1, whose
// ToUnicode cmap, object 6, is fuzzed too and also serves the Type0 font
// /F2.
func FuzzPageText(f *testing.F) {
	cmap := "/CIDInit /ProcSet findresource begin 12 dict begin begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange " +
		"2 beginbfchar <0001> <0041> <0002> <D83DDE00> endbfchar 2 beginbfrange <0010> <0020> <0061> <0030> <0031> [<0042> <0043>] endbfrange " +
		"endcmap CMapName currentdict /CMap defineresource pop end end"
	content := "BT /F1 12 Tf 1 0 0 1 72 700 Tm (abc) Tj [(d) -250 (e)] TJ 0 -14 Td <00010002> Tj T* /F2 10 Tf <00100011> Tj 2 3 (x) \" ET 10 10 50 50 re q 2 0 0 2 0 0 cm Q"
	f.Add([]byte(content), []byte("<< /Type /Font /Subtype /Type1 /BaseFont /ABCDEF+Helvetica /FirstChar 97 /LastChar 101 /Widths [500 600 700 800 900] /Encoding /WinAnsiEncoding >>"), []byte(cmap))
	f.Add([]byte(content), []byte("<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /ToUnicode 6 0 R /DescendantFonts [<< /DW 500 /W [1 [600 700] 16 32 400] >>] >>"), []byte(cmap))
	f.Add([]byte(content), []byte("<< /Encoding << /Differences [97 /quoteright /bullet 100 /fi] >> >>"), []byte(cmap))
	f.Add([]byte("BT /F1 1 Tf <0001> Tj ID \x00\xff EI ET"), []byte("<< /ToUnicode 6 0 R >>"), []byte("1 begincodespacerange <00> <FF> endcodespacerange 1 beginbfrange <00> <FF> <0041> endbfrange"))
	f.Fuzz(func(t *testing.T, content, font, cmap []byte) {
		// Interpret itself, as text extraction drives it.
		ops := 0
		tolerate(func() {
			Interpret(memoryStream(content), func(stk *Stack, op string) {
				if ops++; ops > len(content) {
					t.Fatalf("%d operators from %d bytes", ops, len(content))
				}
				if stk.Len() > maxOperands {
					t.Fatalf("%d operands", stk.Len())
				}
				popArgs(stk)
			})
		})

		data := pagePDF("/Resources << /Font << /F1 5 0 R /F2 7 0 R >> >>",
			streamObj(string(content)),
			string(font),
			streamObj(string(cmap)),
			"<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /ToUnicode 6 0 R /DescendantFonts [<< /W [16 [300 400]] >>] >>",
		)
		r := openPDF(t, data)
		p := r.Page(1)
		tolerate(func() {
			c := p.Content()
			if n := len(c.Text) + len(c.Rect); n > maxPageGlyphs {
				t.Fatalf("Content holds %d texts and rects", n)
			}
		})
		text, err := p.GetPlainText(nil)
		checkErr(t, "GetPlainText", err)
		// BT adds a newline that is not a glyph.
		if n := utf8.RuneCountInString(text); n > maxPageGlyphs+len(content) {
			t.Fatalf("GetPlainText returned %d runes", n)
		}
		rows, err := p.GetTextByRow()
		checkErr(t, "GetTextByRow", err)
		n := 0
		for _, row := range rows {
			n += len(row.Content)
		}
		if n > maxPageGlyphs {
			t.Fatalf("GetTextByRow returned %d texts", n)
		}
	})
}

// objSep separates the trailer entries and the objects of FuzzOpen's input.
const objSep = "\nendobj\n"

var (
	fileObject  = regexp.MustCompile(`(?s)\d+ 0 obj\n(.*?)\nendobj\n`)
	fileTrailer = regexp.MustCompile(`(?s)/Root 1 0 R(.*?)>>\s*startxref`)
)

// openInput returns file, whose objects are numbered in order from 1, as
// FuzzOpen's input.
func openInput(file []byte) []byte {
	parts := [][]byte{fileTrailer.FindSubmatch(file)[1]}
	for _, m := range fileObject.FindAllSubmatch(file, -1) {
		parts = append(parts, m[1])
	}
	return bytes.Join(parts, []byte(objSep))
}

// FuzzOpen reads a whole file the way a text extractor does. The input is
// its trailer entries and objects, and the xref is built around them: nearly
// every mutation of a raw file shifts an offset, and would stop at the xref.
func FuzzOpen(f *testing.F) {
	content := "BT /F1 12 Tf 72 700 Td (Hello) Tj ET"
	for _, seed := range [][]byte{
		validPDF(),
		streamPage("/Filter /FlateDecode", deflate([]byte(content))),
		encryptedPDF(cryptSpec{V: 1, R: 2, bits: 40}, content, "One", ""),
		encryptedPDF(cryptSpec{V: 2, R: 3, bits: 128}, content, "Two", ""),
		encryptedPDF(cryptSpec{V: 4, R: 4, bits: 128, noMetadata: true}, content, "Three", ""),
		pageTreePDF("<< /Type /Pages /Kids [3 0 R] /Resources << /Font << /F1 5 0 R >> >> >>",
			"<< /Type /Pages /Parent 2 0 R /Kids [4 0 R] >>",
			"<< /Type /Page /Parent 3 0 R /Contents [6 0 R 7 0 R] >>",
			"<< /Type /Font /Subtype /Type1 /Encoding << /Differences [72 /H.sc] >> >>",
			streamObj("BT /F1 12 Tf (Hel"), streamObj("lo) Tj ET")),
	} {
		f.Add(openInput(seed))
	}
	for _, name := range []string{"testdata/ascii85_flate_chain.pdf", "testdata/ascii85_zero_group.pdf"} {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(openInput(data))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		parts := strings.Split(string(input), objSep)
		data := buildPDF(parts[1:]...)
		i := bytes.LastIndex(data, []byte(">>\nstartxref"))
		data = slices.Concat(data[:i], []byte(parts[0]), data[i:])
		r, err := NewReader(bytes.NewReader(data), int64(len(data)))
		checkErr(t, "NewReader", err)
		if err != nil {
			return
		}
		pages := 0
		tolerate(func() { pages = r.NumPage() })
		if pages > maxPageTreeNodes {
			t.Fatalf("%d pages", pages)
		}
		for i := 1; i <= pages; i++ {
			tolerate(func() {
				c := r.Page(i).Content()
				if n := len(c.Text) + len(c.Rect); n > maxPageGlyphs {
					t.Fatalf("page %d holds %d texts and rects", i, n)
				}
			})
		}
		_, err = r.GetPlainText()
		checkErr(t, "GetPlainText", err)
		if n := countOutline(r.Outline()); n > maxOutlineNodes {
			t.Fatalf("outline holds %d items", n)
		}
	})
}
