// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// The structures a PDF uses to describe pages and outlines are graphs of
// object references, not trees, so a file can point them back at themselves.
// The traversals below are bounded to stop a cycle from looping forever, or
// from recursing until the goroutine stack is exhausted, which is a fatal
// error that a caller cannot recover from.
const (
	// maxPageTreeDepth bounds a descent through /Kids. Real page trees are
	// broad and shallow.
	maxPageTreeDepth = 1024

	// maxPageTreeNodes bounds the /Kids entries, and so the pages, the page
	// tree walk visits.
	maxPageTreeNodes = 1 << 20

	// maxInheritDepth bounds a walk up a chain of /Parent links, counting the
	// page itself. A page at the bottom of the deepest tree Page accepts has
	// maxPageTreeDepth ancestors, all of which may carry inherited entries.
	maxInheritDepth = maxPageTreeDepth + 1

	// maxOutlineDepth and maxOutlineNodes bound an outline of distinct
	// items, deep or wide.
	maxOutlineDepth = 128
	maxOutlineNodes = 1 << 16

	// maxOutlineTitleBytes bounds the outline's titles in all, since items
	// can share one long title by reference.
	maxOutlineTitleBytes = 1 << 20

	// maxPageGlyphs bounds the glyphs, Texts, and Rects text extraction
	// builds for one page, about 64 bytes each. A dense real page holds under
	// ten thousand; an inflated content stream can show millions from a few
	// kilobytes.
	maxPageGlyphs = 1 << 18

	// maxDocGlyphs bounds the glyphs text extraction shows across one
	// Reader's pages, however many pages share a content stream. A 2,054-page
	// book shows 3.5 million.
	maxDocGlyphs = 32 * maxPageGlyphs

	// maxGstackDepth bounds the graphics states q saves in Page.Content; a q
	// past it saves none. Each is 400 bytes, so a stream of q from a few
	// kilobytes would otherwise hold gigabytes.
	maxGstackDepth = 1 << 10
)

// A Page represent a single page in a PDF file.
// The methods interpret a Page dictionary stored in V.
type Page struct {
	V Value
	// inherited, when set, is the /Resources entry the page inherits from the
	// page tree, found as the tree was walked, so that Resources need not
	// parse the page's ancestors again.
	inherited *unresolved
}

// An unresolved value is resolved only when asked for, so that a value many
// pages share is not kept parsed for each of them.
type unresolved struct {
	parent objptr
	x      object
}

// Page returns the page for the given page number.
// Page numbers are indexed starting at 1, not 0.
// If the page is not found, Page returns a Page with p.V.IsNull().
func (r *Reader) Page(num int) Page {
	pages := r.pages()
	if num < 1 || num > len(pages) {
		return Page{}
	}
	e := pages[num-1]
	return Page{V: r.resolve(e.parent, e.kid), inherited: e.resources}
}

// NumPage returns the number of pages in the PDF file: those its page tree
// lists, whatever its /Count claims.
func (r *Reader) NumPage() int {
	return len(r.pages())
}

// A pageEntry is a page the page tree lists. It keeps the /Kids entry rather
// than the parsed page, which Page parses again, so that a tree listing a
// million small pages does not hold them all.
type pageEntry struct {
	parent    objptr
	kid       object
	resources *unresolved
}

// pages returns the pages the page tree lists, in order, walking the tree
// once per Reader.
func (r *Reader) pages() []pageEntry {
	if r.cache == nil {
		return r.walkPages()
	}
	return r.cache.pages.get(r.walkPages)
}

// walkPages lists the pages of the page tree. A /Kids entry referring to a
// node or page already listed is skipped: a node listed twice at each level
// would make a tree of 33 objects hold 2^31 pages, and one listing an
// ancestor would make a cycle.
func (r *Reader) walkPages() []pageEntry {
	w := pageWalk{seen: make(map[objptr]bool)}
	w.walk(r.Trailer().Key("Root").Key("Pages"), new(unresolved), 1)
	return w.pages
}

type pageWalk struct {
	seen  map[objptr]bool
	nodes int
	pages []pageEntry
}

func (w *pageWalk) walk(node Value, resources *unresolved, depth int) {
	if depth > maxPageTreeDepth || node.Key("Type").Name() != "Pages" {
		return
	}
	if d, _ := node.data.(dict); d["Resources"] != nil {
		resources = &unresolved{node.ptr, d["Resources"]}
	}
	kids := node.Key("Kids")
	entries, _ := kids.data.(array)
	for i, x := range entries {
		if w.nodes++; w.nodes > maxPageTreeNodes {
			return
		}
		if ref, ok := x.(objptr); ok {
			if w.seen[ref] {
				continue
			}
			w.seen[ref] = true
		}
		kid := kids.Index(i)
		switch kid.Key("Type").Name() {
		case "Pages":
			w.walk(kid, resources, depth+1)
		case "Page":
			w.pages = append(w.pages, pageEntry{kids.ptr, x, resources})
		}
	}
}

// GetPlainText returns all the text in the PDF file
func (r *Reader) GetPlainText() (reader io.Reader, err error) {
	// Resolving objects panics on malformed input, and that happens here in
	// NumPage, Page and Fonts as well as inside Page.GetPlainText.
	defer func() {
		if e := recover(); e != nil {
			reader, err = &bytes.Buffer{}, fmt.Errorf("malformed PDF: %v", e)
		}
	}()

	pages := r.NumPage()
	var buf bytes.Buffer
	fonts := make(map[string]*Font)
	shared := make(fontSet)
	for i := 1; i <= pages; i++ {
		p := r.Page(i)
		// Fonts are shared by name so that each charmap is parsed once.
		dict := p.Resources().Key("Font")
		for _, name := range dict.Keys() {
			if _, ok := fonts[name]; !ok {
				fonts[name], _ = shared.font(dict, name)
			}
		}
		text, err := p.GetPlainText(fonts)
		if err != nil {
			return nil, err
		}
		buf.WriteString(text)
	}
	return &buf, nil
}

// GetStyledTexts returns list all sentences in an array, that are included styles
func (r *Reader) GetStyledTexts() (sentences []Text, err error) {
	// Page.Content has no way to report a malformed content stream, so catch
	// its panics here rather than letting them reach the caller.
	defer func() {
		if e := recover(); e != nil {
			sentences, err = nil, fmt.Errorf("malformed PDF: %v", e)
		}
	}()

	totalPage := r.NumPage()
	for pageIndex := 1; pageIndex <= totalPage; pageIndex++ {
		p := r.Page(pageIndex)
		if p.V.Key("Contents").Kind() == Null {
			continue
		}
		// lastTextStyle is the sentence's first Text; s holds its text.
		var lastTextStyle Text
		var s strings.Builder
		texts := p.Content().Text
		for _, text := range texts {
			if lastTextStyle == (Text{}) {
				lastTextStyle = text
				s.WriteString(text.S)
				continue
			}

			if IsSameSentence(lastTextStyle, text) {
				s.WriteString(text.S)
			} else {
				lastTextStyle.S = s.String()
				sentences = append(sentences, lastTextStyle)
				lastTextStyle = text
				s.Reset()
				s.WriteString(text.S)
			}
		}
		if s.Len() > 0 {
			lastTextStyle.S = s.String()
			sentences = append(sentences, lastTextStyle)
		}
	}

	return sentences, err
}

func (p Page) findInherited(key string) Value {
	v := p.V
	for depth := 0; !v.IsNull() && depth < maxInheritDepth; depth++ {
		if r := v.Key(key); !r.IsNull() {
			return r
		}
		v = v.Key("Parent")
	}
	return Value{}
}

/*
func (p Page) MediaBox() Value {
	return p.findInherited("MediaBox")
}

func (p Page) CropBox() Value {
	return p.findInherited("CropBox")
}
*/

// Resources returns the resources dictionary associated with the page.
func (p Page) Resources() Value {
	if p.inherited == nil {
		return p.findInherited("Resources")
	}
	if v := p.V.Key("Resources"); !v.IsNull() {
		return v
	}
	return p.V.r.resolve(p.inherited.parent, p.inherited.x)
}

// Fonts returns a list of the fonts associated with the page.
func (p Page) Fonts() []string {
	return p.Resources().Key("Font").Keys()
}

// Font returns the font with the given name associated with the page.
func (p Page) Font(name string) Font {
	return Font{V: p.Resources().Key("Font").Key(name)}
}

// pageFonts resolves a page's fonts by name as its text operators select
// them, each once, so that its charmap is parsed once. The /Font dictionary
// is looked up on the first selection, since each lookup walks the /Parent
// chain, and a font on its own first selection, since a page may name
// thousands it never shows.
type pageFonts struct {
	page   Page
	dict   Value
	looked bool
	fonts  map[string]*Font
	shared fontSet
}

// A glyphBudget counts the glyphs one page's text extraction shows, or the
// values it builds for them, against maxPageGlyphs and its Reader's
// document-wide budget.
type glyphBudget struct {
	r *Reader
	n int
}

func (g *glyphBudget) spend(n int) {
	if g.n += n; g.n > maxPageGlyphs {
		panic(fmt.Errorf("page shows more than %d glyphs", maxPageGlyphs))
	}
	if g.r != nil && g.r.cache != nil && g.r.cache.glyphs.Add(-int64(n)) < 0 {
		panic(fmt.Errorf("document shows more than %d glyphs", maxDocGlyphs))
	}
}

// noFont is the font of a name the page does not define. Its encoding is set
// so that Encoder never writes to the shared value.
var noFont = Font{enc: &byteEncoder{&pdfDocEncoding}}

// lookup returns the font named name, or noFont for a name whose entry is
// null, with false if the page has no entry for it at all. An undefined name
// is not remembered: a content stream can select millions of them.
func (pf *pageFonts) lookup(fontName string) (*Font, bool) {
	if f, ok := pf.fonts[fontName]; ok {
		return f, true
	}
	if !pf.looked {
		pf.dict = pf.page.Resources().Key("Font")
		pf.looked = true
		pf.fonts = make(map[string]*Font)
		pf.shared = make(fontSet)
	}
	f, ok := pf.shared.font(pf.dict, fontName)
	if ok {
		pf.fonts[fontName] = f
	}
	return f, ok
}

// A fontSet holds one Font per font object, so that names referring to one
// object share it rather than each parsing the object and keeping a copy.
type fontSet map[objptr]*Font

// font returns the font that entry key of the /Font dictionary fonts names,
// or noFont for a null entry, with false if fonts has no entry key.
func (s fontSet) font(fonts Value, key string) (*Font, bool) {
	d, _ := fonts.data.(dict)
	x, ok := d[name(key)]
	if !ok {
		return &noFont, false
	}
	ptr, isRef := x.(objptr)
	if f, ok := s[ptr]; isRef && ok {
		return f, true
	}
	f := &noFont
	if v := fonts.r.resolve(fonts.ptr, x); !v.IsNull() {
		f = &Font{V: v, m: new(fontMetrics)}
	}
	if isRef {
		s[ptr] = f
	}
	return f, true
}

// A Font represent a font in a PDF file.
// The methods interpret a Font dictionary stored in V.
type Font struct {
	V   Value
	enc TextEncoding
	// m, when set, keeps the entries Page.Content reads per glyph, so that
	// each is resolved once rather than per glyph.
	m *fontMetrics
}

type fontMetrics struct {
	loaded      bool
	base        string
	first, last int
	widths      []float64 // for codes first onward
}

// metrics returns f.m, loading it on first use, or nil if f does not keep one.
func (f Font) metrics() *fontMetrics {
	m := f.m
	if m == nil || m.loaded {
		return m
	}
	m.base = f.V.Key("BaseFont").Name()
	m.first, m.last = int(f.V.Key("FirstChar").Int64()), int(f.V.Key("LastChar").Int64())
	if m.last >= m.first {
		w := f.V.Key("Widths")
		n := w.Len()
		if span := m.last - m.first; span >= 0 && span < n {
			n = span + 1
		}
		// Page.Content asks only for the widths of byte codes.
		n = min(n, max(0, 256-m.first))
		m.widths = make([]float64, n)
		for i := range m.widths {
			m.widths[i] = w.Index(i).Float64()
		}
	}
	m.loaded = true
	return m
}

// BaseFont returns the font's name (BaseFont property).
func (f Font) BaseFont() string {
	if m := f.metrics(); m != nil {
		return m.base
	}
	return f.V.Key("BaseFont").Name()
}

// FirstChar returns the code point of the first character in the font.
func (f Font) FirstChar() int {
	if m := f.metrics(); m != nil {
		return m.first
	}
	return int(f.V.Key("FirstChar").Int64())
}

// LastChar returns the code point of the last character in the font.
func (f Font) LastChar() int {
	if m := f.metrics(); m != nil {
		return m.last
	}
	return int(f.V.Key("LastChar").Int64())
}

// Widths returns the widths of the glyphs in the font.
// In a well-formed PDF, len(f.Widths()) == f.LastChar()+1 - f.FirstChar().
func (f Font) Widths() []float64 {
	x := f.V.Key("Widths")
	var out []float64
	for i := 0; i < x.Len(); i++ {
		out = append(out, x.Index(i).Float64())
	}
	return out
}

// Width returns the width of the given code point.
func (f Font) Width(code int) float64 {
	if m := f.metrics(); m != nil {
		if i := code - m.first; i >= 0 && i < len(m.widths) {
			return m.widths[i]
		}
		return 0
	}
	first := f.FirstChar()
	last := f.LastChar()
	if code < first || last < code {
		return 0
	}
	return f.V.Key("Widths").Index(code - first).Float64()
}

// Encoder returns the encoding between font code point sequences and UTF-8.
//
// The receiver is a pointer so the parsed encoding is cached on the Font;
// with a value receiver the assignment to f.enc would be discarded with the
// copy, defeating the caching entirely.
func (f *Font) Encoder() TextEncoding {
	if f.enc == nil { // caching the Encoder so we don't have to continually parse charmap
		f.enc = f.getEncoder()
	}
	return f.enc
}

func (f Font) getEncoder() TextEncoding {
	enc := f.V.Key("Encoding")
	switch enc.Kind() {
	case Name:
		switch enc.Name() {
		case "WinAnsiEncoding":
			return &byteEncoder{&winAnsiEncoding}
		case "MacRomanEncoding":
			return &byteEncoder{&macRomanEncoding}
		case "Identity-H":
			return f.charmapEncoding()
		case "UniGB-UCS2-H":
			return &ucs2Encoder{}
		default:
			if DebugOn {
				println("unknown encoding", enc.Name())
			}
			return &nopEncoder{}
		}
	case Dict:
		return &dictEncoder{enc.Key("Differences")}
	case Null:
		return f.charmapEncoding()
	default:
		if DebugOn {
			println("unexpected encoding", enc.String())
		}
		return &nopEncoder{}
	}
}

func (f *Font) charmapEncoding() TextEncoding {
	toUnicode := f.V.Key("ToUnicode")
	if toUnicode.Kind() == Stream {
		m := toUnicode.r.toUnicodeCmap(toUnicode)
		if m == nil {
			return &nopEncoder{}
		}
		return m
	}

	return &byteEncoder{&pdfDocEncoding}
}

type dictEncoder struct {
	v Value
}

func (e *dictEncoder) Decode(raw string) (text string) {
	r := make([]rune, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		ch := rune(raw[i])
		n := -1
		for j := 0; j < e.v.Len(); j++ {
			x := e.v.Index(j)
			if x.Kind() == Integer {
				n = int(x.Int64())
				continue
			}
			if x.Kind() == Name {
				if int(raw[i]) == n {
					r := nameToRune[x.Name()]
					if r != 0 {
						ch = r
						break
					}
				}
				n++
			}
		}
		r = append(r, ch)
	}
	return string(r)
}

// A TextEncoding represents a mapping between
// font code points and UTF-8 text.
type TextEncoding interface {
	// Decode returns the UTF-8 text corresponding to
	// the sequence of code points in raw.
	Decode(raw string) (text string)
}

type nopEncoder struct {
}

func (e *nopEncoder) Decode(raw string) (text string) {
	return raw
}

type ucs2Encoder struct{}

func (e *ucs2Encoder) Decode(raw string) (text string) {
	return utf16Decode(raw)
}

type byteEncoder struct {
	table *[256]rune
}

func (e *byteEncoder) Decode(raw string) (text string) {
	r := make([]rune, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		r = append(r, e.table[raw[i]])
	}
	return string(r)
}

type byteRange struct {
	low  string
	high string
}

type bfchar struct {
	orig string
	repl string
}

type bfrange struct {
	lo  string
	hi  string
	dst Value
}

type cmap struct {
	space   [4][]byteRange // codespace range
	bfrange []bfrange
	bfchar  []bfchar
}

func (m *cmap) Decode(raw string) (text string) {
	var r []rune
Parse:
	for len(raw) > 0 {
		for n := 1; n <= 4 && n <= len(raw); n++ { // number of digits in character replacement (1-4 possible)
			for _, space := range m.space[n-1] { // find matching codespace Ranges for number of digits
				if space.low <= raw[:n] && raw[:n] <= space.high { // see if value is in range
					text := raw[:n]
					raw = raw[n:]
					for _, bfchar := range m.bfchar { // check for matching bfchar
						if len(bfchar.orig) == n && bfchar.orig == text {
							r = append(r, []rune(utf16Decode(bfchar.repl))...)
							continue Parse
						}
					}
					for _, bfrange := range m.bfrange { // check for matching bfrange
						if len(bfrange.lo) == n && bfrange.lo <= text && text <= bfrange.hi {
							if bfrange.dst.Kind() == String {
								s := bfrange.dst.RawString()
								// An empty destination has no low byte to scale.
								if bfrange.lo != text && len(s) > 0 { // value isn't at the beginning of the range so scale result
									b := []byte(s)
									b[len(b)-1] += text[len(text)-1] - bfrange.lo[len(bfrange.lo)-1] // increment last byte by difference
									s = string(b)
								}
								r = append(r, []rune(utf16Decode(s))...)
								continue Parse
							}
							if bfrange.dst.Kind() == Array {
								n := text[len(text)-1] - bfrange.lo[len(bfrange.lo)-1]
								v := bfrange.dst.Index(int(n))
								if v.Kind() == String {
									s := v.RawString()
									r = append(r, []rune(utf16Decode(s))...)
									continue Parse
								}
								if DebugOn {
									fmt.Printf("array %v\n", bfrange.dst)
								}
							} else {
								if DebugOn {
									fmt.Printf("unknown dst %v\n", bfrange.dst)
								}
							}
							r = append(r, noRune)
							continue Parse
						}
					}
					r = append(r, noRune)
					continue Parse
				}
			}
		}
		if DebugOn {
			println("no code space found")
		}
		r = append(r, noRune)
		raw = raw[1:]
	}
	return string(r)
}

// operandCount returns how many entries of per operands a block can supply:
// its declared count, or fewer when the stack holds fewer. Generators
// miscount these blocks often enough that discarding the block, let alone the
// whole cmap, would turn readable text into raw codes.
func operandCount(stk *Stack, n, per int) int {
	if have := stk.Len() / per; n > have {
		n = have
	}
	return n
}

// readCmap reads and parses a font's ToUnicode stream. The stream is read
// here, outside the recovery in parseCmap: one that cannot be read at all, for
// an unsupported filter or corrupt data, is reported the way any other
// unreadable stream is, so an error-returning caller sees it rather than
// silently decoding text with no cmap.
func readCmap(toUnicode Value) *cmap {
	data, err := io.ReadAll(newLimitedReader(toUnicode.Reader(), maxInterpretBytes))
	if err != nil {
		panic(fmt.Errorf("reading ToUnicode cmap: %v", err))
	}
	return parseCmap(memoryStream(data))
}

// toUnicodeCmap returns the cmap in ToUnicode stream v, parsed once per
// Reader however many fonts and pages share it.
func (r *Reader) toUnicodeCmap(v Value) *cmap {
	load := func() *cmap { return readCmap(v) }
	ptr := v.data.(stream).ptr
	if ptr == (objptr{}) {
		return load()
	}
	return cacheEntry(r.cache, &r.cache.cmaps, ptr).get(load)
}

// memoryStream returns an unfiltered stream Value holding data.
func memoryStream(data []byte) Value {
	r := &Reader{f: bytes.NewReader(data), end: int64(len(data))}
	return Value{r: r, data: stream{dict{name("Length"): int64(len(data))}, objptr{}, 0}}
}

func parseCmap(toUnicode Value) (result *cmap) {
	// A ToUnicode CMap is arbitrary data from the file, and Interpret reports
	// malformed input by panicking. Treat that as "no usable cmap" so it does
	// not escape into callers that cannot report it.
	defer func() {
		if r := recover(); r != nil {
			result = nil
		}
	}()

	n := -1
	var m cmap
	ok := true
	Interpret(toUnicode, func(stk *Stack, op string) {
		if !ok {
			return
		}
		switch op {
		case "findresource":
			stk.Pop() // category
			stk.Pop() // key
			stk.Push(newDict())
		case "begincmap":
			stk.Push(newDict())
		case "endcmap":
			stk.Pop()
		case "begincodespacerange":
			n = int(stk.Pop().Int64())
		case "endcodespacerange":
			if n < 0 {
				if DebugOn {
					println("missing begincodespacerange")
				}
				ok = false
				return
			}
			n = operandCount(stk, n, 2)
			for i := 0; i < n; i++ {
				hi, lo := stk.Pop().RawString(), stk.Pop().RawString()
				if len(lo) == 0 || len(lo) != len(hi) {
					if DebugOn {
						println("bad codespace range")
					}
					ok = false
					return
				}
				// A codespace range is 1 to 4 bytes wide, and its width
				// indexes m.space directly.
				if len(lo) > len(m.space) {
					if DebugOn {
						println("codespace range too wide")
					}
					ok = false
					return
				}
				m.space[len(lo)-1] = append(m.space[len(lo)-1], byteRange{lo, hi})
			}
			n = -1
		case "beginbfchar":
			n = int(stk.Pop().Int64())
		case "endbfchar":
			if n < 0 {
				if DebugOn {
					println("missing beginbfchar")
				}
				ok = false
				return
			}
			n = operandCount(stk, n, 2)
			for i := 0; i < n; i++ {
				repl, orig := stk.Pop().RawString(), stk.Pop().RawString()
				m.bfchar = append(m.bfchar, bfchar{orig, repl})
			}
			n = -1
		case "beginbfrange":
			n = int(stk.Pop().Int64())
		case "endbfrange":
			if n < 0 {
				if DebugOn {
					println("missing beginbfrange")
				}
				ok = false
				return
			}
			n = operandCount(stk, n, 3)
			for i := 0; i < n; i++ {
				dst, srcHi, srcLo := stk.Pop(), stk.Pop().RawString(), stk.Pop().RawString()
				m.bfrange = append(m.bfrange, bfrange{srcLo, srcHi, dst})
			}
			n = -1
		case "defineresource":
			stk.Pop().Name() // category
			value := stk.Pop()
			stk.Pop().Name() // key
			stk.Push(value)
		default:
			if DebugOn {
				println("interp\t", op)
			}
		}
	})
	if !ok {
		return nil
	}
	return &m
}

type matrix [3][3]float64

var ident = matrix{{1, 0, 0}, {0, 1, 0}, {0, 0, 1}}

func (x matrix) mul(y matrix) matrix {
	var z matrix
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			for k := 0; k < 3; k++ {
				z[i][j] += x[i][k] * y[k][j]
			}
		}
	}
	return z
}

// A Text represents a single piece of text drawn on a page.
type Text struct {
	Font     string  // the font used
	FontSize float64 // the font size, in points (1/72 of an inch)
	X        float64 // the X coordinate, in points, increasing left to right
	Y        float64 // the Y coordinate, in points, increasing bottom to top
	W        float64 // the width of the text, in points
	S        string  // the actual UTF-8 text
}

// A Rect represents a rectangle.
type Rect struct {
	Min, Max Point
}

// A Point represents an X, Y pair.
type Point struct {
	X float64
	Y float64
}

// Content describes the basic content on a page: the text and any drawn rectangles.
type Content struct {
	Text []Text
	Rect []Rect
}

type gstate struct {
	Tc    float64
	Tw    float64
	Th    float64
	Tl    float64
	Tf    Font
	Tfs   float64
	Tmode int
	Trise float64
	Tm    matrix
	Tlm   matrix
	Trm   matrix
	CTM   matrix
}

// popArgs pops every value currently on the stack and returns them with the
// bottom of the stack at args[0], matching the operand order expected by PDF
// content-stream operators.
func popArgs(stk *Stack) []Value {
	n := stk.Len()
	args := make([]Value, n)
	for i := n - 1; i >= 0; i-- {
		args[i] = stk.Pop()
	}
	return args
}

// recoverTo recovers from a panic raised while parsing PDF content and stores
// it in err, after calling reset to discard any partially built result. It is
// meant to be deferred by methods that use panic-based parse error handling.
func recoverTo(err *error, reset func()) {
	if r := recover(); r != nil {
		reset()
		*err = errors.New(fmt.Sprint(r))
	}
}

// decodeText decodes raw font code points with enc and returns UTF-8 text.
func decodeText(enc TextEncoding, raw string) string {
	var b strings.Builder
	for _, ch := range enc.Decode(raw) {
		b.WriteRune(ch)
	}
	return b.String()
}

// GetPlainText returns the page's all text without format.
// fonts can be passed in (to improve parsing performance) or left nil
func (p Page) GetPlainText(fonts map[string]*Font) (result string, err error) {
	defer recoverTo(&err, func() { result = "" })

	// Handle in case the content page is empty
	if p.V.IsNull() || p.V.Key("Contents").Kind() == Null {
		return "", nil
	}
	strm := p.V.Key("Contents")
	var enc TextEncoding = &nopEncoder{}

	lookup := (&pageFonts{page: p}).lookup
	if fonts != nil {
		lookup = func(name string) (*Font, bool) {
			f, ok := fonts[name]
			return f, ok
		}
	}

	var textBuilder bytes.Buffer
	showText := func(s string) {
		textBuilder.WriteString(s)
	}
	glyphs := glyphBudget{r: p.V.r}
	showEncodedText := func(s string) {
		s = decodeText(enc, s)
		glyphs.spend(utf8.RuneCountInString(s))
		textBuilder.WriteString(s)
	}

	Interpret(strm, func(stk *Stack, op string) {
		args := popArgs(stk)

		switch op {
		default:
			// Easier debug
			// fmt.Println("<DEBUG><op>", op, "</op><args>", args, "</args>")
			return
		case "BT": // add a space between text objects
			showText("\n")
		case "T*": // move to start of next line
			showEncodedText("\n")
		case "Tf": // set text font and size
			if len(args) != 2 {
				panic("bad TL")
			}
			if font, ok := lookup(args[0].Name()); ok {
				enc = font.Encoder()
			} else {
				enc = &nopEncoder{}
			}
		case "\"": // set spacing, move to next line, and show text
			if len(args) != 3 {
				panic("bad \" operator")
			}
			args = args[2:]
			fallthrough
		case "'": // move to next line and show text
			if len(args) != 1 {
				panic("bad ' operator")
			}
			fallthrough
		case "Tj": // show text
			if len(args) != 1 {
				panic("bad Tj operator")
			}
			showEncodedText(args[0].RawString())
		case "TJ": // show text, allowing individual glyph positioning
			if len(args) != 1 {
				panic("bad TJ operator")
			}
			v := args[0]
			for i := 0; i < v.Len(); i++ {
				x := v.Index(i)
				if x.Kind() == String {
					showEncodedText(x.RawString())
				}
			}
		}
	})
	return textBuilder.String(), nil
}

// Column represents the contents of a column
type Column struct {
	Position int64
	Content  TextVertical
}

// Columns is a list of column
type Columns []*Column

// GetTextByColumn returns the page's all text grouped by column
func (p Page) GetTextByColumn() (result Columns, err error) {
	defer recoverTo(&err, func() { result = Columns{} })

	columns := make(map[int64]*Column)
	showText := func(enc TextEncoding, currentX, currentY float64, s string) {
		text := Text{
			S: decodeText(enc, s),
			X: currentX,
			Y: currentY,
		}

		currentColumn := columns[int64(currentX)]
		if currentColumn == nil {
			currentColumn = &Column{
				Position: int64(currentX),
				Content:  TextVertical{},
			}
			columns[currentColumn.Position] = currentColumn
			result = append(result, currentColumn)
		}

		currentColumn.Content = append(currentColumn.Content, text)
	}

	p.walkTextBlocks(showText)

	for _, column := range result {
		sort.Sort(column.Content)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Position < result[j].Position
	})

	return result, err
}

// Row represents the contents of a row
type Row struct {
	Position int64
	Content  TextHorizontal
}

// Rows is a list of rows
type Rows []*Row

// GetTextByRow returns the page's all text grouped by rows
func (p Page) GetTextByRow() (result Rows, err error) {
	defer recoverTo(&err, func() { result = Rows{} })

	rows := make(map[int64]*Row)
	showText := func(enc TextEncoding, currentX, currentY float64, s string) {
		text := Text{
			S: decodeText(enc, s),
			X: currentX,
			Y: currentY,
		}

		currentRow := rows[int64(currentY)]
		if currentRow == nil {
			currentRow = &Row{
				Position: int64(currentY),
				Content:  TextHorizontal{},
			}
			rows[currentRow.Position] = currentRow
			result = append(result, currentRow)
		}

		currentRow.Content = append(currentRow.Content, text)
	}

	p.walkTextBlocks(showText)

	for _, row := range result {
		sort.Sort(row.Content)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Position > result[j].Position
	})

	return result, err
}

func (p Page) walkTextBlocks(walker func(enc TextEncoding, x, y float64, s string)) {
	// Handle in case the content page is empty
	if p.V.IsNull() || p.V.Key("Contents").Kind() == Null {
		return
	}

	strm := p.V.Key("Contents")

	fonts := &pageFonts{page: p}

	var enc TextEncoding = &nopEncoder{}
	var currentX, currentY float64
	glyphs := glyphBudget{r: p.V.r}
	show := func(s string) {
		glyphs.spend(1)
		walker(enc, currentX, currentY, s)
	}
	Interpret(strm, func(stk *Stack, op string) {
		args := popArgs(stk)

		// if DebugOn {
		// 	fmt.Println(op, "->", args)
		// }

		switch op {
		default:
			return
		case "T*": // move to start of next line
		case "Tf": // set text font and size
			if len(args) != 2 {
				panic("bad TL")
			}

			if font, ok := fonts.lookup(args[0].Name()); ok {
				enc = font.Encoder()
			} else {
				enc = &nopEncoder{}
			}
		case "\"": // set spacing, move to next line, and show text
			if len(args) != 3 {
				panic("bad \" operator")
			}
			args = args[2:]
			fallthrough
		case "'": // move to next line and show text
			if len(args) != 1 {
				panic("bad ' operator")
			}
			fallthrough
		case "Tj": // show text
			if len(args) != 1 {
				panic("bad Tj operator")
			}

			show(args[0].RawString())
		case "TJ": // show text, allowing individual glyph positioning
			if len(args) != 1 {
				panic("bad TJ operator")
			}
			v := args[0]
			for i := 0; i < v.Len(); i++ {
				x := v.Index(i)
				if x.Kind() == String {
					show(x.RawString())
				}
			}
		case "Td":
			show("")
		case "Tm":
			if len(args) != 6 {
				panic("bad Tm")
			}
			currentX = args[4].Float64()
			currentY = args[5].Float64()
		}
	})
}

// Content returns the page's content.
func (p Page) Content() Content {
	// Handle in case the content page is empty
	if p.V.IsNull() || p.V.Key("Contents").Kind() == Null {
		return Content{}
	}
	strm := p.V.Key("Contents")
	var enc TextEncoding = &nopEncoder{}
	fonts := &pageFonts{page: p}

	var g = gstate{
		Th:  1,
		CTM: ident,
	}

	var text []Text
	glyphs := glyphBudget{r: p.V.r}
	showText := func(s string) {
		n := 0
		decoded := enc.Decode(s)
		for _, ch := range decoded {
			glyphs.spend(1)
			var w0 float64
			if n < len(s) {
				w0 = g.Tf.Width(int(s[n]))
			}
			n++

			f := g.Tf.BaseFont()
			if i := strings.Index(f, "+"); i >= 0 {
				f = f[i+1:]
			}

			Trm := matrix{{g.Tfs * g.Th, 0, 0}, {0, g.Tfs, 0}, {0, g.Trise, 1}}.mul(g.Tm).mul(g.CTM)
			text = append(text, Text{f, Trm[0][0], Trm[2][0], Trm[2][1], w0 / 1000 * Trm[0][0], string(ch)})

			tx := w0/1000*g.Tfs + g.Tc
			tx *= g.Th
			g.Tm = matrix{{1, 0, 0}, {0, 1, 0}, {tx, 0, 1}}.mul(g.Tm)
		}
	}

	var rect []Rect
	var gstack []gstate
	Interpret(strm, func(stk *Stack, op string) {
		args := popArgs(stk)
		switch op {
		default:
			// if DebugOn {
			// 	fmt.Println(op, args)
			// }
			return

		case "cm": // update g.CTM
			if len(args) != 6 {
				panic("bad g.Tm")
			}
			var m matrix
			for i := 0; i < 6; i++ {
				m[i/2][i%2] = args[i].Float64()
			}
			m[2][2] = 1
			g.CTM = m.mul(g.CTM)

		case "gs": // set parameters from graphics state resource
			//gs := p.Resources().Key("ExtGState").Key(args[0].Name())
			//font := gs.Key("Font")
			//if font.Kind() == Array && font.Len() == 2 {
			// if DebugOn {
			// 	fmt.Println("FONT", font)
			// }
			//}

		case "f": // fill
		case "g": // setgray
		case "l": // lineto
		case "m": // moveto

		case "cs": // set colorspace non-stroking
		case "scn": // set color non-stroking

		case "re": // append rectangle to path
			if len(args) != 4 {
				panic("bad re")
			}
			x, y, w, h := args[0].Float64(), args[1].Float64(), args[2].Float64(), args[3].Float64()
			glyphs.spend(1)
			rect = append(rect, Rect{Point{x, y}, Point{x + w, y + h}})

		case "q": // save graphics state
			if len(gstack) < maxGstackDepth {
				gstack = append(gstack, g)
			}

		case "Q": // restore graphics state
			n := len(gstack) - 1
			// A content stream may hold more Q than q, in which case there is
			// no saved state to pop.
			if n < 0 {
				break
			}
			g = gstack[n]
			gstack = gstack[:n]

		case "BT": // begin text (reset text matrix and line matrix)
			g.Tm = ident
			g.Tlm = g.Tm

		case "ET": // end text

		case "T*": // move to start of next line
			x := matrix{{1, 0, 0}, {0, 1, 0}, {0, -g.Tl, 1}}
			g.Tlm = x.mul(g.Tlm)
			g.Tm = g.Tlm

		case "Tc": // set character spacing
			if len(args) != 1 {
				panic("bad g.Tc")
			}
			g.Tc = args[0].Float64()

		case "TD": // move text position and set leading
			if len(args) != 2 {
				panic("bad Td")
			}
			g.Tl = -args[1].Float64()
			fallthrough
		case "Td": // move text position
			if len(args) != 2 {
				panic("bad Td")
			}
			tx := args[0].Float64()
			ty := args[1].Float64()
			x := matrix{{1, 0, 0}, {0, 1, 0}, {tx, ty, 1}}
			g.Tlm = x.mul(g.Tlm)
			g.Tm = g.Tlm

		case "Tf": // set text font and size
			if len(args) != 2 {
				panic("bad TL")
			}
			f := args[0].Name()
			font, _ := fonts.lookup(f)
			enc = font.Encoder()
			g.Tf = *font
			if enc == nil {
				if DebugOn {
					println("no cmap for", f)
				}
				enc = &nopEncoder{}
			}
			g.Tfs = args[1].Float64()

		case "\"": // set spacing, move to next line, and show text
			if len(args) != 3 {
				panic("bad \" operator")
			}
			g.Tw = args[0].Float64()
			g.Tc = args[1].Float64()
			args = args[2:]
			fallthrough
		case "'": // move to next line and show text
			if len(args) != 1 {
				panic("bad ' operator")
			}
			x := matrix{{1, 0, 0}, {0, 1, 0}, {0, -g.Tl, 1}}
			g.Tlm = x.mul(g.Tlm)
			g.Tm = g.Tlm
			fallthrough
		case "Tj": // show text
			if len(args) != 1 {
				panic("bad Tj operator")
			}
			showText(args[0].RawString())

		case "TJ": // show text, allowing individual glyph positioning
			if len(args) != 1 {
				panic("bad TJ operator")
			}
			v := args[0]
			for i := 0; i < v.Len(); i++ {
				x := v.Index(i)
				if x.Kind() == String {
					showText(x.RawString())
				} else {
					tx := -x.Float64() / 1000 * g.Tfs * g.Th
					g.Tm = matrix{{1, 0, 0}, {0, 1, 0}, {tx, 0, 1}}.mul(g.Tm)
				}
			}
			showText("\n")

		case "TL": // set text leading
			if len(args) != 1 {
				panic("bad TL")
			}
			g.Tl = args[0].Float64()

		case "Tm": // set text matrix and line matrix
			if len(args) != 6 {
				panic("bad g.Tm")
			}
			var m matrix
			for i := 0; i < 6; i++ {
				m[i/2][i%2] = args[i].Float64()
			}
			m[2][2] = 1
			g.Tm = m
			g.Tlm = m

		case "Tr": // set text rendering mode
			if len(args) != 1 {
				panic("bad Tr")
			}
			g.Tmode = int(args[0].Int64())

		case "Ts": // set text rise
			if len(args) != 1 {
				panic("bad Ts")
			}
			g.Trise = args[0].Float64()

		case "Tw": // set word spacing
			if len(args) != 1 {
				panic("bad g.Tw")
			}
			g.Tw = args[0].Float64()

		case "Tz": // set horizontal text scaling
			if len(args) != 1 {
				panic("bad Tz")
			}
			g.Th = args[0].Float64() / 100
		}
	})
	return Content{text, rect}
}

// TextVertical implements sort.Interface for sorting
// a slice of Text values in vertical order, top to bottom,
// and then left to right within a line.
type TextVertical []Text

func (x TextVertical) Len() int      { return len(x) }
func (x TextVertical) Swap(i, j int) { x[i], x[j] = x[j], x[i] }
func (x TextVertical) Less(i, j int) bool {
	if x[i].Y != x[j].Y {
		return x[i].Y > x[j].Y
	}
	return x[i].X < x[j].X
}

// TextHorizontal implements sort.Interface for sorting
// a slice of Text values in horizontal order, left to right,
// and then top to bottom within a column.
type TextHorizontal []Text

func (x TextHorizontal) Len() int      { return len(x) }
func (x TextHorizontal) Swap(i, j int) { x[i], x[j] = x[j], x[i] }
func (x TextHorizontal) Less(i, j int) bool {
	if x[i].X != x[j].X {
		return x[i].X < x[j].X
	}
	return x[i].Y > x[j].Y
}

// An Outline is a tree describing the outline (also known as the table of contents)
// of a document.
type Outline struct {
	Title string    // title for this element
	Child []Outline // child elements
}

// Outline returns the document outline.
// The Outline returned is the root of the outline tree and typically has no Title itself.
// That is, the children of the returned root are the top-level entries in the outline.
// A malformed reference somewhere in the tree yields the empty outline, as a
// missing /Outlines does. The tree is cut off past 65,536 items or 128
// levels, and titles past the first 1 MB of them read as empty.
func (r *Reader) Outline() (x Outline) {
	var err error
	defer recoverTo(&err, func() { x = Outline{} })
	w := outlineWalk{budget: maxOutlineNodes, seen: make(map[objptr]bool)}
	return w.build(r.Trailer().Key("Root").Key("Outlines"), 0)
}

// An outlineWalk builds an Outline from a tree whose /First and /Next links
// can both be made cyclic.
type outlineWalk struct {
	// budget is the number of nodes still allowed for the whole tree.
	budget int
	// seen holds the references followed so far. Outline items are indirect
	// objects, so a reference met again is a cycle, and the item it names is
	// already built.
	seen map[objptr]bool
	// titles counts the title bytes read; once past maxOutlineTitleBytes,
	// titles are left empty and not read at all.
	titles int
}

func (w *outlineWalk) build(entry Value, depth int) Outline {
	var x Outline
	if w.budget <= 0 {
		return x
	}
	w.budget--
	if depth > maxOutlineDepth {
		return x
	}
	if w.titles <= maxOutlineTitleBytes {
		title := entry.Key("Title").Text()
		if w.titles += len(title); w.titles <= maxOutlineTitleBytes {
			x.Title = title
		}
	}
	child, ok := w.follow(entry, "First")
	for ok && child.Kind() == Dict {
		if w.budget <= 0 {
			break
		}
		x.Child = append(x.Child, w.build(child, depth+1))
		child, ok = w.follow(child, "Next")
	}
	return x
}

// follow resolves entry's key, reporting false for a reference already
// followed.
func (w *outlineWalk) follow(entry Value, key string) (Value, bool) {
	if d, ok := entry.data.(dict); ok {
		if ref, ok := d[name(key)].(objptr); ok {
			if w.seen[ref] {
				return Value{}, false
			}
			w.seen[ref] = true
		}
	}
	return entry.Key(key), true
}
