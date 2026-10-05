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
