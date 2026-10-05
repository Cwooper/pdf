// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Reading of PDF tokens and objects from a raw byte stream.

package pdf

import (
	"errors"
	"fmt"
	"io"
	"strconv"
)

// A token is a PDF token in the input stream, one of the following Go types:
//
//	bool, a PDF boolean
//	int64, a PDF integer
//	float64, a PDF real
//	string, a PDF string literal
//	keyword, a PDF keyword
//	name, a PDF name without the leading slash
type token interface{}

// A name is a PDF name, without the leading slash.
type name string

// A keyword is a PDF keyword.
// Delimiter tokens used in higher-level syntax,
// such as "<<", ">>", "[", "]", "{", "}", are also treated as keywords.
type keyword string

// maxObjectDepth is the maximum nesting depth for PDF objects (dicts, arrays,
// and indirect object definitions). Malicious files can nest millions of
// "N N obj" tokens to exhaust the Go call stack; this limit turns that into
// a recoverable panic instead of a fatal process crash.
const maxObjectDepth = 1000

// A buffer holds buffered input bytes from the PDF file.
type buffer struct {
	r           io.Reader // source of data
	buf         []byte    // buffered data
	pos         int       // read index in buf
	offset      int64     // offset at end of buf; aka offset of next read
	tmp         []byte    // scratch space for accumulating token
	unread      []token   // queue of read but then unread tokens
	allowEOF    bool
	allowObjptr bool
	allowStream bool
	eof         bool
	key         []byte
	useAES      bool
	decrypter   stringDecrypter
	objptr      objptr
	depth       int // current object nesting depth
	// entries counts the array and dict entries read, against maxEntries
	// when it is set.
	entries    int
	maxEntries int
	readFailed bool // reading the input failed, and would fail again
}

// newBuffer returns a new buffer reading from r at the given offset.
func newBuffer(r io.Reader, offset int64) *buffer {
	return &buffer{
		r:           r,
		offset:      offset,
		buf:         make([]byte, 0, 4096),
		allowObjptr: true,
		allowStream: true,
	}
}

func (b *buffer) readByte() byte {
	if b.pos >= len(b.buf) {
		b.reload()
		if b.pos >= len(b.buf) {
			return '\n'
		}
	}
	c := b.buf[b.pos]
	b.pos++
	return c
}

func (b *buffer) errorf(format string, args ...interface{}) {
	panic(fmt.Errorf(format, args...))
}

func (b *buffer) reload() bool {
	// A read that failed, by error or by panic, would fail again, so
	// Interpret must raise it rather than skip it as a malformed token.
	defer func() {
		if r := recover(); r != nil {
			b.readFailed = true
			panic(r)
		}
	}()
	size := cap(b.buf) - int(b.offset%int64(cap(b.buf)))
	n, err := b.r.Read(b.buf[:size])
	// io.Reader allows a read to return nothing and no error; give up after
	// as many in a row as bufio does.
	for empty := 1; n == 0 && err == nil; empty++ {
		if empty == 100 {
			err = io.ErrNoProgress
			break
		}
		n, err = b.r.Read(b.buf[:size])
	}
	if n == 0 && err != nil {
		b.buf = b.buf[:0]
		b.pos = 0
		if errors.Is(err, errStreamNotPresent) {
			b.eof = true
			return false
		}
		if b.allowEOF && err == io.EOF {
			b.eof = true
			return false
		}
		b.errorf("malformed PDF: reading at offset %d: %v", b.offset, err)
		return false
	}
	b.offset += int64(n)
	b.buf = b.buf[:n]
	b.pos = 0
	return true
}

func (b *buffer) readOffset() int64 {
	return b.offset - int64(len(b.buf)) + int64(b.pos)
}

func (b *buffer) unreadByte() {
	if b.pos > 0 {
		b.pos--
	}
}

func (b *buffer) unreadToken(t token) {
	b.unread = append(b.unread, t)
}

func (b *buffer) readToken() token {
	if n := len(b.unread); n > 0 {
		t := b.unread[n-1]
		b.unread = b.unread[:n-1]
		return t
	}

	// Find first non-space, non-comment byte.
	c := b.readByte()
	for {
		if isSpace(c) {
			if b.eof {
				return io.EOF
			}
			c = b.readByte()
		} else if c == '%' {
			for c != '\r' && c != '\n' {
				c = b.readByte()
			}
		} else {
			break
		}
	}

	switch c {
	case '<':
		if b.readByte() == '<' {
			return keyword("<<")
		}
		b.unreadByte()
		return b.readHexString()

	case '(':
		return b.readLiteralString()

	case '[', ']', '{', '}':
		return keyword(string(c))

	case '/':
		return b.readName()

	case '>':
		if b.readByte() == '>' {
			return keyword(">>")
		}
		b.unreadByte()
		fallthrough

	default:
		if isDelim(c) {
			b.errorf("unexpected delimiter %#q", rune(c))
			return nil
		}
		b.unreadByte()
		return b.readKeyword()
	}
}

// readHexString reads the body of a hex string after its '<'. An odd number of
// digits is valid: the final digit behaves as if followed by 0 (PDF 32000-1,
// 7.3.4.3).
func (b *buffer) readHexString() token {
	tmp := b.tmp[:0]
	for {
	Loop:
		c := b.readByte()
		if c == '>' {
			break
		}
		// readByte reports end of input as '\n' once allowEOF is set, so
		// without this check an unterminated hex string skips whitespace
		// forever.
		if b.eof {
			break
		}
		if isSpace(c) {
			goto Loop
		}
	Loop2:
		c2 := b.readByte()
		if b.eof {
			break
		}
		if isSpace(c2) {
			goto Loop2
		}
		if c2 == '>' {
			x := unhex(c) << 4
			if x < 0 {
				b.errorf("malformed hex string %c", c)
				break
			}
			tmp = append(tmp, byte(x))
			break
		}
		x := unhex(c)<<4 | unhex(c2)
		if x < 0 {
			b.errorf("malformed hex string %c %c", c, c2)
			break
		}
		tmp = append(tmp, byte(x))
	}
	b.tmp = tmp
	return string(tmp)
}

func unhex(b byte) int {
	switch {
	case '0' <= b && b <= '9':
		return int(b) - '0'
	case 'a' <= b && b <= 'f':
		return int(b) - 'a' + 10
	case 'A' <= b && b <= 'F':
		return int(b) - 'A' + 10
	}
	return -1
}

func (b *buffer) readLiteralString() token {
	tmp := b.tmp[:0]
	depth := 1
Loop:
	for {
		c := b.readByte()
		// The end of input reads as '\n'; it ends the string, not part of it.
		if b.eof {
			break
		}
		switch c {
		default:
			tmp = append(tmp, c)
		case '(':
			depth++
			tmp = append(tmp, c)
		case ')':
			if depth--; depth == 0 {
				break Loop
			}
			tmp = append(tmp, c)
		case '\\':
			switch c = b.readByte(); c {
			default:
				// PDF 32000-1, 7.3.4.2: a backslash before any other
				// character is ignored.
				tmp = append(tmp, c)
			case 'n':
				tmp = append(tmp, '\n')
			case 'r':
				tmp = append(tmp, '\r')
			case 'b':
				tmp = append(tmp, '\b')
			case 't':
				tmp = append(tmp, '\t')
			case 'f':
				tmp = append(tmp, '\f')
			case '(', ')', '\\':
				tmp = append(tmp, c)
			case '\r':
				if b.readByte() != '\n' {
					b.unreadByte()
				}
				fallthrough
			case '\n':
				// no append
			case '0', '1', '2', '3', '4', '5', '6', '7':
				x := int(c - '0')
				for i := 0; i < 2; i++ {
					c = b.readByte()
					if c < '0' || c > '7' {
						b.unreadByte()
						break
					}
					x = x*8 + int(c-'0')
				}
				// PDF 32000-1, 7.3.4.2: high-order overflow is ignored.
				tmp = append(tmp, byte(x))
			}
		}
	}
	b.tmp = tmp
	return string(tmp)
}

// skipInlineImage skips the data of an inline image, which follows its ID
// operator, leaving EI as the next token. The data is binary, and its length
// depends on the image's filters, so it ends at the first EI between
// whitespace.
func (b *buffer) skipInlineImage() {
	var last [3]byte
	for {
		c := b.readByte()
		if b.eof {
			return
		}
		if isSpace(last[0]) && last[1] == 'E' && last[2] == 'I' && isSpace(c) {
			b.unreadByte()
			b.unreadToken(keyword("EI"))
			return
		}
		last = [3]byte{last[1], last[2], c}
	}
}

func (b *buffer) readName() token {
	tmp := b.tmp[:0]
	for {
		c := b.readByte()
		if isDelim(c) || isSpace(c) {
			b.unreadByte()
			break
		}
		if c == '#' {
			x := unhex(b.readByte())<<4 | unhex(b.readByte())
			if x < 0 {
				b.errorf("malformed name")
			}
			tmp = append(tmp, byte(x))
			continue
		}
		tmp = append(tmp, c)
	}
	b.tmp = tmp
	return name(string(tmp))
}

func (b *buffer) readKeyword() token {
	tmp := b.tmp[:0]
	for {
		c := b.readByte()
		if isDelim(c) || isSpace(c) {
			b.unreadByte()
			break
		}
		tmp = append(tmp, c)
	}
	b.tmp = tmp
	s := string(tmp)
	switch {
	case s == "true":
		return true
	case s == "false":
		return false
	case isInteger(s):
		x, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			// Too large for an int64, so read as a real.
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				b.errorf("invalid integer %.64q", s)
			}
			return f
		}
		return x
	case isReal(s):
		x, err := strconv.ParseFloat(s, 64)
		if err != nil {
			b.errorf("invalid real %.64q", s)
		}
		return x
	}
	return keyword(string(tmp))
}

func isInteger(s string) bool {
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || '9' < c {
			return false
		}
	}
	return true
}

func isReal(s string) bool {
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	if len(s) == 0 {
		return false
	}
	ndot := 0
	for _, c := range s {
		if c == '.' {
			ndot++
			continue
		}
		if c < '0' || '9' < c {
			return false
		}
	}
	return ndot == 1
}

// An object is a PDF syntax object, one of the following Go types:
//
//	bool, a PDF boolean
//	int64, a PDF integer
//	float64, a PDF real
//	string, a PDF string literal
//	name, a PDF name without the leading slash
//	dict, a PDF dictionary
//	array, a PDF array
//	stream, a PDF stream
//	objptr, a PDF object reference
//	objdef, a PDF object definition
//
// An object may also be nil, to represent the PDF null.
type object interface{}

type dict map[name]object

type array []object

type stream struct {
	hdr    dict
	ptr    objptr
	offset int64
}

type objptr struct {
	id  uint32
	gen uint16
}

type objdef struct {
	ptr objptr
	obj object
}

func (b *buffer) readObject() object {
	b.depth++
	defer func() { b.depth-- }()
	if b.depth > maxObjectDepth {
		b.errorf("object nesting exceeds maximum depth %d", maxObjectDepth)
		return nil
	}

	tok := b.readToken()
	if kw, ok := tok.(keyword); ok {
		switch kw {
		case "null":
			return nil
		case "<<":
			return b.readDict()
		case "[":
			return b.readArray()
		case ">>", "]":
			// stop the object - these mark the end of dict/array
			return nil
		}
		b.errorf("unexpected keyword %.64q parsing object", kw)
		return nil
	}

	if str, ok := tok.(string); ok && b.key != nil && b.objptr.id != 0 {
		tok = b.decrypter.decrypt(b.key, b.useAES, b.objptr, str)
	}

	if !b.allowObjptr {
		return tok
	}

	if t1, ok := tok.(int64); ok && int64(uint32(t1)) == t1 {
		tok2 := b.readToken()
		if t2, ok := tok2.(int64); ok && int64(uint16(t2)) == t2 {
			tok3 := b.readToken()
			switch tok3 {
			case keyword("R"):
				return objptr{uint32(t1), uint16(t2)}
			case keyword("obj"):
				old := b.objptr
				b.objptr = objptr{uint32(t1), uint16(t2)}
				obj := b.readObject()
				if _, ok := obj.(stream); !ok {
					tok4 := b.readToken()
					if tok4 != keyword("endobj") {
						b.errorf("missing endobj after indirect object definition")
						b.unreadToken(tok4)
					}
				}
				b.objptr = old
				return objdef{objptr{uint32(t1), uint16(t2)}, obj}
			}
			b.unreadToken(tok3)
		}
		b.unreadToken(tok2)
	}
	return tok
}

func (b *buffer) readArray() object {
	var x array
	for {
		tok := b.readToken()
		// Break on io.EOF as well (readToken returns io.EOF as a token value
		// once the input is exhausted, and readDict already guards for it):
		// otherwise an array that is never closed, e.g. in a truncated
		// content stream, loops forever appending io.EOF objects and
		// allocates memory without bound.
		if tok == nil || tok == io.EOF || tok == keyword("]") {
			break
		}
		b.unreadToken(tok)
		b.countEntry()
		x = append(x, b.readObject())
	}
	return x
}

func (b *buffer) readDict() object {
	x := make(dict)
	for {
		tok := b.readToken()
		if tok == nil || tok == keyword(">>") {
			break
		}
		if tok == io.EOF {
			break
		}
		n, ok := tok.(name)
		if !ok {
			if DebugOn {
				fmt.Printf("DEBUG: %T(%v)\n. Skip dict", tok, tok)
			}
			b.errorf("unexpected non-name key %T parsing dictionary", tok)
			continue
		}
		b.countEntry()
		v := b.readObject()
		if v == io.EOF {
			// The value is cut off by the end of input; io.EOF is a marker,
			// not a value resolve can return.
			v = nil
		}
		x[n] = v
	}

	if !b.allowStream {
		return x
	}

	tok := b.readToken()
	if tok != keyword("stream") {
		b.unreadToken(tok)
		return x
	}

	switch b.readByte() {
	case '\r':
		if b.readByte() != '\n' {
			b.unreadByte()
		}
	case '\n':
		// ok
	default:
		b.errorf("stream keyword not followed by newline")
	}

	return stream{x, b.objptr, b.readOffset()}
}

func (b *buffer) countEntry() {
	if b.entries++; b.maxEntries > 0 && b.entries > b.maxEntries {
		b.errorf("more than %d operands", b.maxEntries)
	}
}

func isSpace(b byte) bool {
	switch b {
	case '\x00', '\t', '\n', '\f', '\r', ' ':
		return true
	}
	return false
}

func isDelim(b byte) bool {
	switch b {
	case '<', '>', '(', ')', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}
