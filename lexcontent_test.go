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
