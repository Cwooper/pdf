package pdf

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// TestDictStackCap verifies that Interpret refuses begin nesting past
// maxDictStack, since every keyword is looked up through the whole stack.
func TestDictStackCap(t *testing.T) {
	ok := strings.Repeat("<<>> begin ", maxDictStack) + "n"
	Interpret(rawStream(ok), func(stk *Stack, op string) {})

	deep := strings.Repeat("<<>> begin ", maxDictStack+1)
	mustPanic(t, "begin", func() { Interpret(rawStream(deep), func(stk *Stack, op string) {}) })
}

// TestOperandCapCountsEntries verifies that Interpret refuses operands past
// maxOperands, the entries of array and dict operands included while the
// stack, or a dict begin opened, holds them.
func TestOperandCapCountsEntries(t *testing.T) {
	nop := func(stk *Stack, op string) {}
	half := strings.Repeat("0 ", maxOperands/2+1)
	tests := []struct{ name, content string }{
		{"numbers", strings.Repeat("1 ", maxOperands+1)},
		{"one array", "[" + strings.Repeat("0 ", 2*maxOperands+2) + "]"},
		{"one dict", "<<" + strings.Repeat("/a 0 ", 2*maxOperands+2) + ">>"},
		{"many arrays", strings.Repeat("[0 0] ", maxOperands/2+1)},
		{"def into a dict", "<<>> begin /a [" + half + "] def /b [" + half + "] def"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mustPanic(t, "operands", func() { Interpret(rawStream(tt.content), nop) })
		})
	}

	t.Run("consumed", func(t *testing.T) {
		content := strings.Repeat("[0 0 0 0] TJ ", maxOperands)
		mustNotCrash(t, func() {
			Interpret(rawStream(content), func(stk *Stack, op string) { popArgs(stk) })
		})
	})
}

// TestObjectEntryCap verifies that an object read from the file counts its
// entries against maxOperands too.
func TestObjectEntryCap(t *testing.T) {
	big := "[" + strings.Repeat("0 ", maxOperands+1) + "]"
	files := map[string][]byte{
		"direct": buildPDF("<< /Type /Catalog /Pages 2 0 R >>", big),
		"in object stream": xrefStreamFile(
			testObj{num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>"},
			testObj{num: 3, hdr: "/N NUM /First FIRST", members: []testObj{{num: 2, body: big}}}),
	}
	for name, data := range files {
		t.Run(name, func(t *testing.T) {
			r := openPDF(t, data)
			mustPanic(t, "entries", func() { r.Trailer().Key("Root").Key("Pages") })
		})
	}
}

// lexError returns the message of the panic reading one object from data.
func lexError(data string) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	b := newBuffer(strings.NewReader(data), 0)
	b.allowEOF = true
	b.readObject()
	return ""
}

// TestLexErrorsShort verifies that a lexer error quotes a bounded amount of
// its input, since Interpret recovers these errors and goes on.
func TestLexErrorsShort(t *testing.T) {
	long := strings.Repeat("x", 1<<20)
	tests := []struct{ name, data string }{
		{"hex string", "<zz" + strings.Repeat(" ", 8<<10)},
		{"keyword in array", "[" + long + "]"},
		{"real", strings.Repeat("9", 400) + ".0 "},
		{"dict key", "<<(" + long + ") 1>>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := lexError(tt.data)
			if msg == "" {
				t.Fatal("read without error, want one")
			}
			if len(msg) > 200 {
				t.Errorf("error is %d bytes: %.80q...", len(msg), msg)
			}
		})
	}
}

// TestInterpretErrorCap verifies that Interpret gives up after
// maxInterpretErrors malformed operands rather than recovering from each.
func TestInterpretErrorCap(t *testing.T) {
	nop := func(stk *Stack, op string) { popArgs(stk) }
	Interpret(rawStream(strings.Repeat("[) ", maxInterpretErrors)), nop)
	mustPanic(t, "malformed", func() {
		Interpret(rawStream(strings.Repeat("[) ", maxInterpretErrors+1)), nop)
	})
}

// contentText returns the text p's Content shows, glyph by glyph.
func contentText(p Page) string {
	var b strings.Builder
	for _, t := range p.Content().Text {
		b.WriteString(t.S)
	}
	return b.String()
}

// TestMalformedTokenKeepsPage verifies that a malformed token outside any
// operand is skipped like one inside an array or dict, rather than losing
// the page's text.
func TestMalformedTokenKeepsPage(t *testing.T) {
	for _, junk := range []string{")", "<zz>", "/a#zz"} {
		t.Run(junk, func(t *testing.T) {
			var got string
			mustNotCrash(t, func() { got = contentText(pageWithContent("BT (a) Tj " + junk + " (b) Tj ET")) })
			if got != "ab" {
				t.Errorf("got %q, want %q", got, "ab")
			}
		})
	}
}

// TestInlineImageSkipped verifies that an inline image's binary data is
// skipped rather than lexed, where an unbalanced "(" would open a string
// swallowing the rest of the page.
func TestInlineImageSkipped(t *testing.T) {
	for _, data := range []string{"(\x80", " (EI\x80", "\nEIx("} {
		t.Run(fmt.Sprintf("%q", data), func(t *testing.T) {
			content := "BT (a) Tj ET q BI /W 2 /H 1 /BPC 8 /CS /G ID " + data + "\nEI Q BT (b) Tj ET"
			var got string
			mustNotCrash(t, func() { got = contentText(pageWithContent(content)) })
			if got != "ab" {
				t.Errorf("got %q, want %q", got, "ab")
			}
		})
	}
}

// TestLexOutOfRangeNumbers verifies that an octal escape above \377 keeps its
// low byte, as ISO 32000-1, 7.3.4.2 says, and that an integer too large for
// int64 reads as a real, rather than either failing its operand.
func TestLexOutOfRangeNumbers(t *testing.T) {
	tests := []struct {
		data string
		want object
	}{
		{`(\777\400a)`, "\xff\x00a"},
		{"99999999999999999999 ", float64(1e20)},
		{"-99999999999999999999 ", float64(-1e20)},
	}
	for _, tt := range tests {
		t.Run(tt.data, func(t *testing.T) {
			var got object
			mustNotCrash(t, func() {
				b := newBuffer(strings.NewReader(tt.data), 0)
				b.allowEOF = true
				got = b.readObject()
			})
			if got != tt.want {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}

	var got string
	mustNotCrash(t, func() { got = contentText(pageWithContent(`BT 99999999999999999999 0 Td (\101\502) Tj ET`)) })
	if got != "AB" {
		t.Errorf("Content shows %q, want %q", got, "AB")
	}
}

// pageTreePDF returns a file whose catalog is object 1 and whose page tree
// root is object 2, then objs as objects 3, 4, ....
func pageTreePDF(root string, objs ...string) []byte {
	return buildPDF(append([]string{"<< /Type /Catalog /Pages 2 0 R >>", root}, objs...)...)
}

// TestPageTreeWalk verifies that pages are counted and numbered from the
// page tree as it is, not from /Count, and that a node listed twice counts
// once, where one listed twice at every level makes 2.9 KB hold 2^31 pages.
func TestPageTreeWalk(t *testing.T) {
	const levels = 31
	var dag []string
	for l := range levels {
		dag = append(dag, fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R %[1]d 0 R] /Count %d >>", l+3, 1<<(levels-l)))
	}
	dag = append(dag, "<< /Type /Page >>")
	page := func(n int) string { return fmt.Sprintf("<< /Type /Page /N %d >>", n) }

	tests := []struct {
		name  string
		data  []byte
		pages int
	}{
		{"node listed twice", buildPDF(append([]string{"<< /Type /Catalog /Pages 2 0 R >>"}, dag...)...), 1},
		{"count overstated", pageTreePDF("<< /Type /Pages /Kids [3 0 R] /Count 5 >>", page(1)), 1},
		{"count understated", pageTreePDF("<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R] /Count 1 >>", page(1), page(2), page(3)), 3},
		{"page listed twice", pageTreePDF("<< /Type /Pages /Kids [3 0 R 4 0 R 3 0 R] /Count 3 >>", page(1), page(2)), 2},
		{"cycle", pageTreePDF("<< /Type /Pages /Kids [2 0 R 3 0 R 2 0 R] /Count 2 >>", page(1)), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := openPDF(t, tt.data)
			var n int
			mustNotCrash(t, func() { n = r.NumPage() })
			if n != tt.pages {
				t.Fatalf("NumPage = %d, want %d", n, tt.pages)
			}
			for i := 1; i <= n; i++ {
				if got := r.Page(i).V.Key("N").Int64(); n > 1 && got != int64(i) {
					t.Errorf("Page(%d) is page %d", i, got)
				}
			}
			if !r.Page(n + 1).V.IsNull() {
				t.Errorf("Page(%d) found past the last page", n+1)
			}
		})
	}
}

// TestPagesParsedOnce verifies that looking up every page, and the resources
// each inherits, parses each node of the page tree once rather than once per
// page.
func TestPagesParsedOnce(t *testing.T) {
	const pages = 2000
	var kids strings.Builder
	objs := []string{"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"}
	for i := range pages {
		fmt.Fprintf(&kids, "%d 0 R ", 4+i)
		objs = append(objs, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /N %d >>", i+1))
	}
	root := fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d /Resources << /Font << /F1 3 0 R >> >> /Junk [%s] >>",
		kids.String(), pages, strings.Repeat("0 ", 50000))
	r := openPDF(t, pageTreePDF(root, objs...))
	got := allocated(func() {
		for i := 1; i <= r.NumPage(); i++ {
			p := r.Page(i)
			if n := p.V.Key("N").Int64(); n != int64(i) {
				t.Fatalf("Page(%d) is page %d", i, n)
			}
			if f := p.Fonts(); len(f) != 1 {
				t.Fatalf("page %d fonts %v, want F1 inherited", i, f)
			}
		}
	})
	if got > 64<<20 {
		t.Errorf("looking up %d pages allocated %d MB", pages, got>>20)
	}
}

// TestInheritedResourcesUnparsed verifies that the page walk keeps the
// /Resources each page inherits unparsed, since many /Pages nodes can name
// one large dict.
func TestInheritedResourcesUnparsed(t *testing.T) {
	const nodes = 32
	var kids strings.Builder
	objs := []string{"<< /Junk (" + strings.Repeat("x", 1<<20) + ") >>"}
	for i := range nodes {
		fmt.Fprintf(&kids, "%d 0 R ", 4+2*i)
		objs = append(objs,
			fmt.Sprintf("<< /Type /Pages /Parent 2 0 R /Kids [%d 0 R] /Count 1 /Resources 3 0 R >>", 5+2*i),
			fmt.Sprintf("<< /Type /Page /Parent %d 0 R >>", 4+2*i))
	}
	r := openPDF(t, pageTreePDF(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), nodes), objs...))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	n := r.NumPage()
	runtime.GC()
	runtime.ReadMemStats(&after)
	if held := int64(after.HeapAlloc) - int64(before.HeapAlloc); held > 8<<20 {
		t.Errorf("the page walk held %d MB", held>>20)
	}
	if got := len(r.Page(n).Resources().Key("Junk").RawString()); n != nodes || got != 1<<20 {
		t.Errorf("%d pages, the last inheriting a %d-byte string; want %d, %d", n, got, nodes, 1<<20)
	}
}

// declaredPages returns the /Count of r's page tree root, which shows that
// the catalog resolved even where the tree lists no pages.
func declaredPages(r *Reader) int {
	return int(r.Trailer().Key("Root").Key("Pages").Key("Count").Int64())
}

// TestContentsArray verifies that a /Contents array is read stream by
// stream: an entry that is not a stream is skipped rather than ending the
// page, and each stream is opened only when the one before it ends.
func TestContentsArray(t *testing.T) {
	t.Run("gap", func(t *testing.T) {
		r := openPDF(t, pagePDF("", "[5 0 R 6 0 R 99 0 R 7 0 R]", streamObj("BT (a) Tj ET"), "<< >>", streamObj("BT (b) Tj ET")))
		var got string
		mustNotCrash(t, func() { got = contentText(r.Page(1)) })
		if got != "ab" {
			t.Errorf("got %q, want %q", got, "ab")
		}
	})

	t.Run("unreadable stream", func(t *testing.T) {
		r := openPDF(t, pagePDF("", "[5 0 R 6 0 R]", streamObj("BT (a) Tj ET"), "<< /Length 1 /Filter /LZWDecode >>\nstream\nx\nendstream"))
		mustPanic(t, "LZWDecode", func() { r.Page(1).Content() })
	})

	t.Run("opened in turn", func(t *testing.T) {
		const n = 2000
		contents := openPDF(t, pagePDF("", "["+strings.Repeat("5 0 R ", n)+"]", flateObj("BT (a) Tj ET"))).Page(1).V.Key("Contents")

		var before, first runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		ops := 0
		Interpret(contents, func(stk *Stack, op string) {
			if ops++; ops == 1 {
				runtime.ReadMemStats(&first)
			}
			popArgs(stk)
		})
		if ops != 3*n {
			t.Errorf("read %d operators, want %d", ops, 3*n)
		}
		if got := first.HeapAlloc - before.HeapAlloc; got > 16<<20 {
			t.Errorf("%d MB in use by the first operator", got>>20)
		}
	})

	// Empty streams decode nothing, so only the entries count.
	t.Run("entries charged", func(t *testing.T) {
		const n = minDecodeBudget/contentsEntryCost + 1
		r := openPDF(t, pagePDF("", "["+strings.Repeat("5 0 R ", n)+"]", streamObj("")))
		mustPanic(t, "budget", func() { r.Page(1).Content() })
	})
}

// TestDocumentGlyphBudget verifies that the glyphs text extraction shows
// count against a budget shared by every page and call on a Reader, however
// many pages share one content stream.
func TestDocumentGlyphBudget(t *testing.T) {
	data := pageTreePDF("<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
		"<< /Type /Page /Contents 5 0 R >>", "<< /Type /Page /Contents 5 0 R >>", streamObj("BT (0123456789) Tj ET"))
	open := func() *Reader {
		r := openPDF(t, data)
		r.cache.glyphs.Store(15)
		return r
	}
	r := open()
	if got := contentText(r.Page(1)); got != "0123456789" {
		t.Fatalf("page 1 shows %q", got)
	}
	mustPanic(t, "glyphs", func() { r.Page(2).Content() })
	if _, err := open().GetPlainText(); err == nil || !strings.Contains(err.Error(), "glyphs") {
		t.Errorf("GetPlainText: got %v, want the glyph budget reported", err)
	}
	if _, err := open().GetStyledTexts(); err == nil || !strings.Contains(err.Error(), "glyphs") {
		t.Errorf("GetStyledTexts: got %v, want the glyph budget reported", err)
	}
}

// TestStyledSentenceLinear verifies that GetStyledTexts builds a sentence in
// time and memory linear in its glyphs.
func TestStyledSentenceLinear(t *testing.T) {
	const glyphs = 50000
	r := openPDF(t, pagePDF("", streamObj("BT ("+strings.Repeat("a", glyphs)+") Tj ET")))
	var sentences []Text
	var err error
	if got := allocated(func() { sentences, err = r.GetStyledTexts() }); got > 64<<20 {
		t.Errorf("GetStyledTexts allocated %d MB", got>>20)
	}
	if err != nil || len(sentences) != 1 || len(sentences[0].S) != glyphs {
		t.Errorf("got %d sentences, err %v; want one of %d glyphs", len(sentences), err, glyphs)
	}
}

// TestTextBlocksBounded verifies that GetTextByRow and GetTextByColumn find a
// row or column in constant time, and that what they and Content build, a
// value per Td or re included, counts against the page's glyph cap.
func TestTextBlocksBounded(t *testing.T) {
	var rows strings.Builder
	rows.WriteString("BT ")
	for i := range maxPageGlyphs {
		fmt.Fprintf(&rows, "1 0 0 1 %d %[1]d Tm ()Tj ", i)
	}
	rows.WriteString("ET")
	p := pageWithContent(rows.String())
	mustNotCrash(t, func() {
		if got, err := p.GetTextByRow(); err != nil || len(got) != maxPageGlyphs {
			t.Errorf("GetTextByRow: %d rows, err %v; want %d", len(got), err, maxPageGlyphs)
		}
		if got, err := p.GetTextByColumn(); err != nil || len(got) != maxPageGlyphs {
			t.Errorf("GetTextByColumn: %d columns, err %v; want %d", len(got), err, maxPageGlyphs)
		}
	})

	flood := pageWithContent("BT " + strings.Repeat("0 0 Td ", maxPageGlyphs+1) + "ET")
	if _, err := flood.GetTextByRow(); err == nil || !strings.Contains(err.Error(), "glyphs") {
		t.Errorf("Td flood: GetTextByRow got %v, want the glyph cap reported", err)
	}
	mustPanic(t, "glyphs", func() { pageWithContent(strings.Repeat("0 0 1 1 re ", maxPageGlyphs+1)).Content() })
}

// TestOutlineTitleBudget verifies that outline titles count against one
// budget for the whole outline, as items can share one long title by
// reference, and that a title past it reads as empty.
func TestOutlineTitleBudget(t *testing.T) {
	const items, size = 200, 256 << 10
	objs := []string{"<< /First 5 0 R >>", "(" + strings.Repeat("t", size) + ")"}
	for i := range items {
		next := ""
		if i+1 < items {
			next = fmt.Sprintf(" /Next %d 0 R", 6+i)
		}
		objs = append(objs, "<< /Title 4 0 R"+next+" >>")
	}
	data := buildPDF(append([]string{"<< /Type /Catalog /Pages 2 0 R /Outlines 3 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>"}, objs...)...)
	r := openPDF(t, data)
	var o Outline
	if got := allocated(func() { o = r.Outline() }); got > 32<<20 {
		t.Errorf("Outline allocated %d MB", got>>20)
	}
	if len(o.Child) != items || len(o.Child[0].Title) != size {
		t.Fatalf("got %d items, the first titled with %d bytes; want %d, the first with %d", len(o.Child), len(o.Child[0].Title), items, size)
	}
	total := 0
	for _, c := range o.Child {
		total += len(c.Title)
	}
	if total > maxOutlineTitleBytes {
		t.Errorf("titles hold %d bytes in all, want at most %d", total, maxOutlineTitleBytes)
	}
}

// TestQuoteOperator verifies that the " operator shows its string, the last
// of its three operands, in every text API.
func TestQuoteOperator(t *testing.T) {
	p := pageWithContent(`BT 1 0 (hello) " ET`)
	if got := contentText(p); got != "hello" {
		t.Errorf("Content shows %q, want %q", got, "hello")
	}
	if got, err := p.GetPlainText(nil); err != nil || !strings.Contains(got, "hello") {
		t.Errorf("GetPlainText = %q, %v; want hello", got, err)
	}
	if rows, err := p.GetTextByRow(); err != nil || len(rows) != 1 || rows[0].Content[0].S != "hello" {
		t.Errorf("GetTextByRow = %v, %v; want hello", rows, err)
	}
}

// TestMissingOperands verifies that TJ and Tm with too few operands are
// reported as malformed content rather than indexing past their operands.
func TestMissingOperands(t *testing.T) {
	for _, content := range []string{"BT TJ ET", "BT 1 Tm (a) Tj ET"} {
		t.Run(content, func(t *testing.T) {
			p := pageWithContent(content)
			noRuntimePanic(t, func() { p.Content() })
			_, err := p.GetPlainText(nil)
			if err != nil && strings.Contains(err.Error(), "runtime error") {
				t.Errorf("GetPlainText: %v", err)
			}
			if _, err := p.GetTextByRow(); err == nil || strings.Contains(err.Error(), "runtime error") {
				t.Errorf("GetTextByRow: got %v, want a malformed content error", err)
			}
		})
	}
}

// TestPageTreeMalformedKid verifies that a kid that fails to parse loses
// only the pages under it, not the whole tree.
func TestPageTreeMalformedKid(t *testing.T) {
	data := pageTreePDF("<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R 6 0 R] /Count 4 >>",
		"<< /Type /Page /N 1 >>",
		"<< /Type /Pages /Kids [7 0 R] /Count 1 /Junk <zz> >>",
		"<< /Type /Page /N 2 /Junk <zz> >>",
		"<< /Type /Page /N 3 >>",
		"<< /Type /Page /N 4 >>")
	r := openPDF(t, data)
	var n int
	mustNotCrash(t, func() { n = r.NumPage() })
	if n != 2 {
		t.Fatalf("NumPage = %d, want 2", n)
	}
	for i, want := range []int64{1, 3} {
		if got := r.Page(i + 1).V.Key("N").Int64(); got != want {
			t.Errorf("Page(%d) is page %d, want %d", i+1, got, want)
		}
	}
}
