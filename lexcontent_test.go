// Hardening of the lexer, the interpreter, and the content and page APIs
// against hostile input. Each case failed, or ran past its bound, before the
// corresponding fix.

package pdf

import (
	"fmt"
	"strings"
	"testing"
)

// mustPanic fails unless fn panics with a message containing want.
func mustPanic(t *testing.T, want string, fn func()) {
	t.Helper()
	p, timedOut := run(t, fn)
	switch {
	case timedOut:
		t.Errorf("did not return within %v", caseTimeout)
	case p == nil:
		t.Errorf("returned, want a panic reporting %q", want)
	case !strings.Contains(fmt.Sprint(p), want):
		t.Errorf("panicked with %v, want %q", p, want)
	}
}

// TestDictStackCap verifies that Interpret refuses begin nesting past
// maxDictStack: every keyword is looked up through the whole stack, so 1.3 KB
// of Flate nesting thousands of dicts took seconds.
func TestDictStackCap(t *testing.T) {
	ok := strings.Repeat("<<>> begin ", maxDictStack) + "n"
	Interpret(rawStream(ok), func(stk *Stack, op string) {})

	deep := strings.Repeat("<<>> begin ", maxDictStack+1)
	mustPanic(t, "begin", func() { Interpret(rawStream(deep), func(stk *Stack, op string) {}) })
}

// TestOperandCapCountsEntries verifies that the entries of array and dict
// operands count against maxOperands while the stack holds them: one array
// of 30 million zeros, 58 KB of Flate, held 1.7 GB.
func TestOperandCapCountsEntries(t *testing.T) {
	nop := func(stk *Stack, op string) {}
	tests := []struct{ name, content string }{
		{"one array", "[" + strings.Repeat("0 ", 2*maxOperands+2) + "]"},
		{"one dict", "<<" + strings.Repeat("/a 0 ", 2*maxOperands+2) + ">>"},
		{"many arrays", strings.Repeat("[0 0] ", maxOperands/2+1)},
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
// its input. Interpret recovers these errors and goes on, so a hex string
// error that dumped the 4 KB buffer, repeated through 62 KB of Flate, built
// gigabytes of messages, and an error quoting a whole token could quote 64 MB.
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
// maxInterpretErrors malformed operands rather than recovering from each:
// one per two bytes of "[)" took 9 seconds over 62 KB of Flate.
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
// skipped rather than lexed: an unbalanced "(" in it opened a string that
// swallowed the rest of the page.
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

// emptyReader returns no bytes and no error, which io.Reader allows.
type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, nil }

// TestEmptyReadsEnd verifies that the lexer gives up on a reader that keeps
// returning no bytes and no error, rather than asking it forever.
func TestEmptyReadsEnd(t *testing.T) {
	mustPanic(t, "no data", func() {
		b := newBuffer(emptyReader{}, 0)
		b.allowEOF = true
		b.readToken()
	})
}
