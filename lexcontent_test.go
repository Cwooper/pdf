package pdf

import (
	"fmt"
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
