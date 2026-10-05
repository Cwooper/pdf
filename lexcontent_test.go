package pdf

import (
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
