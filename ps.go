// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdf

import (
	"fmt"
	"io"
	"runtime"
	"strings"
)

// maxInterpretBytes bounds the decoded bytes one Interpret call reads: a
// page's content streams or a cmap. Flate expands about 1000:1, so a small
// file could otherwise feed the lexer gigabytes. The largest page content in
// 33 thousand pages of ordinary documents is 8.5 MB.
const maxInterpretBytes = 16 << 20

// maxOperands bounds the operands on Interpret's stack together with the array
// and dict entries they hold, and the entries of any object read. Each is a
// 32-byte Value or larger, so operands never consumed by an operator, from a
// few kilobytes of Flate, would hold gigabytes. A cmap block mapping all
// 65536 glyphs at once needs 131072.
const maxOperands = 1 << 18

// maxDictStack bounds the dicts begin opens in Interpret: every keyword is
// looked up in each of them. Real cmaps nest two or three.
const maxDictStack = 64

// maxInterpretErrors bounds the malformed operands Interpret skips before
// giving up. Each costs a recovered panic, many times the work of a valid
// operand, and no ordinary document has any.
const maxInterpretErrors = 1 << 10

// A Stack represents a stack of values.
type Stack struct {
	stack []Value
}

func (stk *Stack) Len() int {
	return len(stk.stack)
}

func (stk *Stack) Push(v Value) {
	stk.stack = append(stk.stack, v)
}

func (stk *Stack) Pop() Value {
	n := len(stk.stack)
	if n == 0 {
		return Value{}
	}
	v := stk.stack[n-1]
	stk.stack[n-1] = Value{}
	stk.stack = stk.stack[:n-1]
	return v
}

func newDict() Value {
	return Value{data: make(dict)}
}

// Interpret interprets the content in a stream as a basic PostScript program,
// pushing values onto a stack and then calling the do function to execute
// operators. The do function may push or pop values from the stack as needed
// to implement op.
//
// Interpret handles the operators "dict", "currentdict", "begin", "end", "def", and "pop" itself.
//
// Interpret is not a full-blown PostScript interpreter. Its job is to handle the
// very limited PostScript found in certain supporting file formats embedded
// in PDF files, such as cmap files that describe the mapping from font code
// points to Unicode code points.
//
// A stream can also be represented by an array of streams that has to be handled as a single stream
// In the case of a simple stream read only once, otherwise get the length of the stream to handle it properly
//
// There is no support for executable blocks, among other limitations.
func Interpret(strm Value, do func(stk *Stack, op string)) {
	var stk Stack
	var dicts []dict
	var rd io.Reader
	errs := 0
	malformed := func() {
		if errs++; errs > maxInterpretErrors {
			panic(fmt.Errorf("more than %d malformed operands", maxInterpretErrors))
		}
	}
	if strm.Kind() == Array {
		rd = &contentsReader{streams: strm}
	} else {
		rd = strm.Reader()
	}

	b := newBuffer(newLimitedReader(rd, maxInterpretBytes), 0)
	b.allowEOF = true
	b.allowObjptr = false
	b.allowStream = false

Reading:
	for {
		if stk.Len() == 0 && len(dicts) == 0 {
			// The entries read so far belonged to operands now consumed,
			// with no dict open that def could have kept them in.
			b.entries = 0
		}
		if stk.Len()+b.entries > maxOperands {
			panic(fmt.Errorf("more than %d operands", maxOperands))
		}
		tok, ok := readRecover(b, b.readToken)
		if !ok {
			malformed()
			continue
		}
		if tok == io.EOF {
			break
		}
		if kw, ok := tok.(keyword); ok {
			switch kw {
			case "null", "[", "]", "<<", ">>":
				break
			default:
				for i := len(dicts) - 1; i >= 0; i-- {
					if v, ok := dicts[i][name(kw)]; ok {
						stk.Push(Value{data: v})
						continue Reading
					}
				}
				do(&stk, string(kw))
				continue
			case "dict":
				stk.Pop()
				stk.Push(Value{data: make(dict)})
				continue
			case "currentdict":
				if len(dicts) == 0 {
					panic("no current dictionary")
				}
				stk.Push(Value{data: dicts[len(dicts)-1]})
				continue
			case "begin":
				d := stk.Pop()
				if d.Kind() != Dict {
					panic("cannot begin non-dict")
				}
				if len(dicts) >= maxDictStack {
					panic(fmt.Errorf("begin nests more than %d dicts", maxDictStack))
				}
				dicts = append(dicts, d.data.(dict))
				continue
			case "end":
				if len(dicts) <= 0 {
					panic("mismatched begin/end")
				}
				dicts = dicts[:len(dicts)-1]
				continue
			case "def":
				val := stk.Pop()
				if len(dicts) <= 0 {
					// A "def" with no dict opened by "begin" is invalid
					// PostScript, but producers emit it in practice inside a
					// malformed CMap dictionary LITERAL (e.g.
					// "<</Registry (x) def/Ordering (y) def>>", where "def"
					// should not appear between "<<" and ">>" at all). This
					// package is a limited PostScript subset for embedded
					// CMap/function data, not a strict validator (see the
					// doc comment above), so discard the operand and keep
					// going rather than take the whole Interpret call down
					// over one producer's malformed dict.
					continue
				}
				key, ok := stk.Pop().data.(name)
				if !ok {
					// panic(fmt.Sprintf("def of non-name: %+v", stk.Pop().data))
					// Skip the value if it has key without value
					continue
				}
				dicts[len(dicts)-1][key] = val.data
				continue
			case "pop":
				stk.Pop()
				continue
			case "ID":
				do(&stk, string(kw))
				b.skipInlineImage()
				continue
			}
		}
		b.unreadToken(tok)
		obj, ok := readRecover(b, b.readObject)
		if !ok {
			malformed()
			continue
		}
		stk.Push(Value{data: obj})
	}
}

// contentsEntryCost is the decode budget each /Contents array entry costs,
// about the work of opening a stream's decoder, since an array can name one
// empty stream hundreds of thousands of times.
const contentsEntryCost = 1 << 10

// A contentsReader reads the streams of an array in turn, opening each only
// once the one before it ends, so that a long array never holds a decoder
// for every stream at once. An entry that is not a stream is skipped.
type contentsReader struct {
	streams Value
	next    int
	cur     io.Reader
}

func (c *contentsReader) Read(p []byte) (int, error) {
	for {
		for c.cur == nil {
			if c.next >= c.streams.Len() {
				return 0, io.EOF
			}
			c.streams.r.spend(contentsEntryCost)
			if v := c.streams.Index(c.next); v.Kind() == Stream {
				// A newline keeps tokens from running across streams.
				c.cur = io.MultiReader(strings.NewReader("\n"), v.Reader())
			}
			c.next++
		}
		n, err := c.cur.Read(p)
		if err == io.EOF {
			c.cur, err = nil, nil
		}
		if n > 0 || err != nil {
			return n, err
		}
	}
}

// readRecover calls read, recovering a panic from malformed input so that one
// bad operand, such as a cmap's stray def inside a dict literal, is skipped
// rather than ending Interpret. A failure to read the input is not recovered:
// it would only recur.
func readRecover[T any](b *buffer, read func() T) (v T, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			// Parse errors are raised with panic(fmt.Errorf(...)) and mean
			// "discard this operand and keep going". Anything else (nil
			// deref, index out of range, ...) is a genuine bug and must not
			// be silently swallowed as malformed input.
			if _, isRuntime := r.(runtime.Error); isRuntime || b.readFailed {
				panic(r)
			}
			ok = false
		}
	}()
	return read(), true
}
