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
