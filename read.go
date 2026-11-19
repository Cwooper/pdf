// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pdf implements reading of PDF files.
//
// # Overview
//
// PDF is Adobe's Portable Document Format, ubiquitous on the internet.
// A PDF document is a complex data format built on a fairly simple structure.
// This package exposes the simple structure along with some wrappers to
// extract basic information. If more complex information is needed, it is
// possible to extract that information by interpreting the structure exposed
// by this package.
//
// Specifically, a PDF is a data structure built from Values, each of which has
// one of the following Kinds:
//
//	Null, for the null object.
//	Integer, for an integer.
//	Real, for a floating-point number.
//	Bool, for a boolean value.
//	Name, for a name constant (as in /Helvetica).
//	String, for a string constant.
//	Dict, for a dictionary of name-value pairs.
//	Array, for an array of values.
//	Stream, for an opaque data stream and associated header dictionary.
//
// The accessors on Value—Int64, Float64, Bool, Name, and so on—return
// a view of the data as the given type. When there is no appropriate view,
// the accessor returns a zero result. For example, the Name accessor returns
// the empty string if called on a Value v for which v.Kind() != Name.
// Returning zero values this way, especially from the Dict and Array accessors,
// which themselves return Values, makes it possible to traverse a PDF quickly
// without writing any error checking. On the other hand, it means that mistakes
// can go unreported.
//
// The basic structure of the PDF file is exposed as the graph of Values.
//
// Most richer data structures in a PDF file are dictionaries with specific interpretations
// of the name-value pairs. The Font and Page wrappers make the interpretation
// of a specific Value as the corresponding type easier. They are only helpers, though:
// they are implemented only in terms of the Value API and could be moved outside
// the package. Equally important, traversal of other PDF data structures can be implemented
// in other packages as needed.
package pdf

// BUG(rsc): The package is incomplete, although it has been used successfully on some
// large real-world PDF files.

// BUG(rsc): There is no support for closing open PDF files. If you drop all references to a Reader,
// the underlying reader will eventually be garbage collected.

// BUG(rsc): Apart from the object streams, fonts, cmaps, and page tree a Reader decodes, which it keeps, the library
// makes no attempt at efficiency. A value cache maintained in the Reader would probably help.

// BUG(rsc): Only the Standard security handler is supported: a file encrypted
// to public-key certificates does not open.

// BUG(rsc): The Value API does not support error reporting. The intent is to allow users to
// set an error reporting callback in Reader, but that code has not been implemented.

import (
	"bytes"
	"cmp"
	"compress/flate"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/ascii85"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/text/unicode/norm"
)

// DebugOn is responsible for logging messages into stdout. If problems arise during reading, set it true.
var DebugOn = false

// A Reader is a single PDF file open for reading.
// It is safe for concurrent use; goroutines share its caches and its budgets
// over its lifetime: its streams decode at most the larger of 128 MB and 32
// times the file size, and its pages show at most 2^23 glyphs. A page whose
// content decodes past its Limits.PageContent fails. A caller reading the
// file through many times should open a new Reader for each pass.
type Reader struct {
	f          io.ReaderAt
	end        int64
	xref       *xrefTable
	trailer    dict
	trailerptr objptr
	key        []byte // nil when no password opened the file
	// strCrypt, stmCrypt, and effCrypt encrypt strings, streams, and embedded
	// files; filters holds the crypt filters by name, for a stream's own
	// /Crypt filter.
	strCrypt, stmCrypt, effCrypt cryptMethod
	filters                      map[name]cryptMethod
	// keyErr is why key is nil in a file whose strings and streams are in
	// the clear, and effErr why its /EFF names no usable filter; either
	// fails only the reads that need it.
	keyErr, effErr error
	// clearMetadata marks /EncryptMetadata false: metadata streams are
	// stored unencrypted.
	clearMetadata bool

	// noObjStm marks a view that resolves nothing stored in an object
	// stream; an object stream's header is read through one, so one stream's
	// header cannot make another stream load.
	noObjStm bool

	limits Limits
	// strictPages makes a page tree past the limits a LimitError rather
	// than a shortened page list.
	strictPages bool
	cache       *readerCache
}

type xref struct {
	ptr      objptr
	inStream bool
	stream   objptr
	offset   int64
}

// Limits applied to values read out of a PDF file. Every one of these is
// attacker controlled, and without a bound a file of a few hundred bytes can
// drive a multi-gigabyte allocation or an out-of-range slice index.
const (
	// maxXrefPrealloc bounds the entries preallocated from a declared /Size;
	// a larger table grows as entries are read.
	maxXrefPrealloc = 1 << 16

	// maxObjectNumber is the highest object number an objptr can hold. The
	// sparse xref table keeps memory proportional to the entries read, so
	// object numbers need no tighter bound than that: legal files may number
	// their objects sparsely.
	maxObjectNumber = int64(math.MaxUint32)

	// maxXrefEntries bounds the entries a cross-reference table may store.
	// Object streams are compressed, so the file length is not a usable bound
	// here: a few kilobytes of xref stream can describe millions of entries.
	// Real files hold at most a few hundred thousand objects.
	maxXrefEntries = 1 << 20

	// maxXrefRows bounds the rows read across a whole /Prev chain, stored or
	// not: each costs a decode whether or not it adds an entry.
	maxXrefRows = 8 * maxXrefEntries

	// maxXrefFieldWidth bounds an entry in an xref stream /W array. The
	// widths are byte counts that decodeInt accumulates into an int, so a
	// field wider than an int64 cannot be represented anyway.
	maxXrefFieldWidth = 8

	// maxObjStmExtends bounds the /Extends chain of an object stream, which
	// is built from object references and can be made cyclic.
	maxObjStmExtends = 32

	// maxObjStmBytes bounds the decoded size of an object stream. Real ones
	// run to a few hundred kilobytes.
	maxObjStmBytes = 16 << 20

	// minDecodeBudget and decodeBudgetRatio bound the bytes a Reader's
	// streams yield in all, counted at every stage from the raw bytes through
	// each filter: the larger of the floor and the ratio times the file size,
	// several times what ordinary documents decode. Every other cap holds per
	// stream or per page, so content shared by many pages could still decode
	// without end.
	minDecodeBudget   = 128 << 20
	decodeBudgetRatio = 32

	// maxPredictorColumns bounds the /Columns of a FlateDecode predictor,
	// which sizes a row buffer.
	maxPredictorColumns = 1 << 20

	// maxFilters bounds a stream's /Filter array, whose decoders are all
	// built before any byte is read. Real files chain two or three.
	maxFilters = 8
)

// An xrefTable maps object numbers to cross-reference entries: numbers near
// those stored live in a dense slice, and the rest in a map, so memory tracks
// the entries read.
type xrefTable struct {
	dense  []xref
	sparse map[uint32]xref
	n      int // entries stored
	rows   int // rows read, stored or not
}

// newXrefTable returns a table sized for the declared number of entries,
// without letting the declaration alone decide the allocation.
func newXrefTable(size int64) *xrefTable {
	if size > maxXrefPrealloc {
		size = maxXrefPrealloc
	}
	return &xrefTable{dense: make([]xref, size)}
}

// get returns the entry for object number id, or the zero entry if none was
// stored. An entry stored sparse while its number was out of reach of the
// slice stays there after the slice grows across it, so an unset slot defers
// to the map.
func (t *xrefTable) get(id uint32) xref {
	if t == nil {
		return xref{}
	}
	if int64(id) < int64(len(t.dense)) {
		if e := t.dense[id]; e.ptr != (objptr{}) || t.sparse == nil {
			return e
		}
	}
	return t.sparse[id]
}

// put stores the entry for object number id. The dense slice grows only in
// proportion to what the table already holds, so the bytes read from the file
// bound the allocation; anything further out is kept sparse.
func (t *xrefTable) put(id uint32, e xref) {
	if limit := 2*t.n + maxXrefPrealloc; int64(id) >= int64(len(t.dense)) && int64(id) < int64(limit) {
		t.dense = ensureXrefLen(t.dense, int(id), limit)
	}
	if int64(id) < int64(len(t.dense)) {
		t.dense[id] = e
		delete(t.sparse, id)
	} else {
		if t.sparse == nil {
			t.sparse = make(map[uint32]xref)
		}
		t.sparse[id] = e
	}
	t.n++
}

// truncate drops the entries for object numbers at or past size.
func (t *xrefTable) truncate(size int64) {
	if size < int64(len(t.dense)) {
		t.dense = t.dense[:size]
	}
	for id := range t.sparse {
		if int64(id) >= size {
			delete(t.sparse, id)
		}
	}
}

// checkObjectNumber reports whether x may be used as a cross-reference table
// index.
func checkObjectNumber(x int64) error {
	if x < 0 || x > maxObjectNumber {
		return fmt.Errorf("object number %d out of range [0, %d]", x, maxObjectNumber)
	}
	return nil
}

// Open opens a file for reading.
func Open(file string) (*os.File, *Reader, error) {
	f, err := os.Open(file)
	if err != nil {
		// f is nil here; calling f.Close() would panic.
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	reader, err := NewReader(f, fi.Size())
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, reader, err
}

// NewReader opens a file for reading, using the data in f with the given total size.
// It reads the page tree only when asked for a page, and a page tree past the
// default limits lists the pages up to them; NewReaderOptions refuses it.
func NewReader(f io.ReaderAt, size int64) (*Reader, error) {
	return NewReaderEncrypted(f, size, nil)
}

// NewReaderEncrypted opens a file for reading, using the data in f with the given total size.
// If the PDF is encrypted, NewReaderEncrypted calls pw repeatedly to obtain passwords
// to try. If pw returns the empty string, NewReaderEncrypted stops trying to decrypt
// the file and returns an error, except for a file that encrypts only its
// attachments: that file opens anyway, and its attachments fail to read.
func NewReaderEncrypted(f io.ReaderAt, size int64, pw func() string) (*Reader, error) {
	return open(f, size, Options{Password: pw})
}

// Limits caps what one file may make a Reader do. A field of zero or less
// takes the default, so fields can be added without changing what a caller
// that sets none gets.
type Limits struct {
	// Pages caps the pages the page tree lists; the entries of its /Kids
	// arrays are capped at twice it. The default is 1<<20.
	Pages int
	// PageContent caps the decoded bytes of a page's content streams, all
	// of them together, that text extraction reads. The default is 16 MB.
	PageContent int64
}

const defaultMaxPages = 1 << 20

func (l Limits) orDefaults() Limits {
	if l.Pages <= 0 {
		l.Pages = defaultMaxPages
	}
	if l.PageContent <= 0 {
		l.PageContent = maxInterpretBytes
	}
	return l
}

// Options configures NewReaderOptions.
type Options struct {
	// Password, if set, is called for passwords to try, as NewReaderEncrypted
	// calls its pw.
	Password func() string
	Limits   Limits
}

// A LimitError reports a file that passes one of a Reader's limits. Limit
// names the Limits field passed, or for a cap Limits does not set:
// PageTreeNodes and PageTreeDepth for the page tree, DecodeBudget for the
// bytes the Reader's streams decode in all, and PageGlyphs and DocGlyphs for
// the glyphs text extraction shows on a page and in all. A Reader's methods
// that return no error raise it as a panic.
type LimitError struct {
	Limit string
	Max   int64
}

func (e LimitError) Error() string {
	switch e.Limit {
	case "Pages":
		return fmt.Sprintf("the page tree lists more than %d pages", e.Max)
	case "PageContent":
		return fmt.Sprintf("a page's content exceeds %d bytes", e.Max)
	case "PageTreeNodes":
		return fmt.Sprintf("the page tree lists more than %d kids", e.Max)
	case "PageTreeDepth":
		return fmt.Sprintf("the page tree nests more than %d levels", e.Max)
	case "DecodeBudget":
		return fmt.Sprintf("decoding exceeds the %d-byte budget for this file", e.Max)
	case "PageGlyphs":
		return fmt.Sprintf("page shows more than %d glyphs", e.Max)
	case "DocGlyphs":
		return fmt.Sprintf("document shows more than %d glyphs", e.Max)
	}
	return fmt.Sprintf("the file passes the %s limit of %d", e.Limit, e.Max)
}

// NewReaderOptions opens a file for reading, using the data in f with the
// given total size, as NewReaderEncrypted does with o.Password. It reads the
// page tree as it opens the file, so that a page tree past o.Limits returns
// its LimitError here.
func NewReaderOptions(f io.ReaderAt, size int64, o Options) (r *Reader, err error) {
	if r, err = open(f, size, o); err != nil {
		return nil, err
	}
	defer func() {
		if x := recover(); x != nil {
			r, err = nil, recoveredError(x)
		}
	}()
	r.strictPages = true
	r.pages()
	return r, nil
}

// recoveredError returns a panic recovered from reading a file as the error
// to report, keeping an error as it is so that errors.As and errors.Is see
// through it.
func recoveredError(x any) error {
	if err, ok := x.(error); ok {
		return err
	}
	return fmt.Errorf("malformed PDF: %v", x)
}

func open(f io.ReaderAt, size int64, o Options) (r *Reader, err error) {
	defer func() {
		if x := recover(); x != nil {
			r, err = nil, recoveredError(x)
		}
	}()

	if size < int64(len("%PDF-1.0\n%%EOF")) {
		return nil, fmt.Errorf("not a PDF file: too short")
	}
	buf := make([]byte, 10)
	f.ReadAt(buf, 0)
	if !validHeader(buf) {
		return nil, fmt.Errorf("not a PDF file: invalid header")
	}
	end := size
	// Acrobat takes the last startxref in the last 1,024 bytes, whatever
	// follows it; the byte before them is read for the line break a
	// startxref first in them needs.
	const endChunk = 1024
	chunk := min(endChunk+1, end)
	buf = make([]byte, chunk)
	if _, err := f.ReadAt(buf, end-chunk); err != nil && err != io.EOF {
		return nil, fmt.Errorf("not a PDF file: %w", err)
	}
	i := findLastLine(buf, "startxref")
	if i < 0 {
		return nil, fmt.Errorf("malformed PDF file: missing final startxref")
	}

	r = &Reader{
		f:      f,
		end:    end,
		limits: o.Limits,
		cache:  new(readerCache),
	}
	r.cache.limit = max(minDecodeBudget, decodeBudgetRatio*size)
	r.cache.budget.Store(r.cache.limit)
	r.cache.glyphs.Store(maxDocGlyphs)
	pos := end - chunk + int64(i)
	b := newBuffer(io.NewSectionReader(f, pos, end-pos), pos)
	b.allowEOF = true
	if b.readToken() != keyword("startxref") {
		return nil, fmt.Errorf("malformed PDF file: missing startxref")
	}
	startxref, ok := b.readToken().(int64)
	if !ok {
		return nil, fmt.Errorf("malformed PDF file: startxref not followed by integer")
	}
	if startxref < 0 {
		return nil, fmt.Errorf("malformed PDF file: negative startxref %d", startxref)
	}
	b = newBuffer(io.NewSectionReader(r.f, startxref, r.end-startxref), startxref)
	xref, trailerptr, trailer, err := readXref(r, b)
	if err != nil {
		return nil, err
	}
	r.xref = xref
	r.trailer = trailer
	r.trailerptr = trailerptr
	if trailer["Encrypt"] == nil {
		return r, nil
	}
	err = r.initEncrypt("")
	if err == nil {
		return r, nil
	}
	if err != ErrInvalidPassword && err != errKeyless {
		return nil, err
	}
	for o.Password != nil {
		next := o.Password()
		if next == "" {
			break
		}
		if r.initEncrypt(next) == nil {
			return r, nil
		}
	}
	if err == errKeyless {
		return r, nil
	}
	return nil, err
}

// Trailer returns the file's Trailer value.
func (r *Reader) Trailer() Value {
	return Value{r: r, ptr: r.trailerptr, data: r.trailer}
}

func readXref(r *Reader, b *buffer) (*xrefTable, objptr, dict, error) {
	tok := b.readToken()
	if tok == keyword("xref") {
		return readXrefTable(r, b)
	}
	if _, ok := tok.(int64); ok {
		b.unreadToken(tok)
		return readXrefStream(r, b)
	}
	return nil, objptr{}, nil, fmt.Errorf("malformed PDF: cross-reference table not found: %v", tok)
}

// readPrevXrefs walks a /Prev chain of cross-reference sections. first is the
// /Prev entry of the most recently read section; parse is called with a buffer
// positioned at the start of each previous section and must return that
// section's own /Prev entry (or nil) to continue the chain.
func readPrevXrefs(r *Reader, first object, parse func(b *buffer) (object, error)) error {
	// /Prev offsets come from the file and can form a cycle. Everything a
	// repeated section describes is already in the table, so the chain just
	// ends there.
	seen := make(map[int64]bool)
	for prev := first; prev != nil; {
		off, ok := prev.(int64)
		if !ok {
			return fmt.Errorf("malformed PDF: xref Prev is not integer: %v", prev)
		}
		if off < 0 {
			return fmt.Errorf("malformed PDF: negative xref Prev %d", off)
		}
		if seen[off] {
			return nil
		}
		seen[off] = true
		b := newBuffer(io.NewSectionReader(r.f, off, r.end-off), off)
		next, err := parse(b)
		if err != nil {
			return err
		}
		prev = next
	}
	return nil
}

func readXrefStream(r *Reader, b *buffer) (*xrefTable, objptr, dict, error) {
	obj1 := b.readObject()
	obj, ok := obj1.(objdef)
	if !ok {
		return nil, objptr{}, nil, fmt.Errorf("malformed PDF: cross-reference table not found: %v", objfmt(obj1))
	}
	strmptr := obj.ptr
	strm, ok := obj.obj.(stream)
	if !ok {
		return nil, objptr{}, nil, fmt.Errorf("malformed PDF: cross-reference table not found: %v", objfmt(obj))
	}
	if strm.hdr["Type"] != name("XRef") {
		return nil, objptr{}, nil, fmt.Errorf("malformed PDF: xref stream does not have type XRef")
	}
	size, ok := strm.hdr["Size"].(int64)
	if !ok {
		return nil, objptr{}, nil, fmt.Errorf("malformed PDF: xref stream missing Size")
	}
	// A negative /Size would panic in make.
	if err := checkObjectNumber(size); err != nil {
		return nil, objptr{}, nil, fmt.Errorf("malformed PDF: xref stream Size: %w", err)
	}
	table := newXrefTable(size)

	table, err := readXrefStreamData(r, strm, table, size)
	if err != nil {
		return nil, objptr{}, nil, fmt.Errorf("malformed PDF: %w", err)
	}

	err = readPrevXrefs(r, strm.hdr["Prev"], func(b *buffer) (object, error) {
		obj1 := b.readObject()
		obj, ok := obj1.(objdef)
		if !ok {
			return nil, fmt.Errorf("malformed PDF: xref prev stream not found: %v", objfmt(obj1))
		}
		prevstrm, ok := obj.obj.(stream)
		if !ok {
			return nil, fmt.Errorf("malformed PDF: xref prev stream not found: %v", objfmt(obj))
		}
		prev := Value{r: r, data: prevstrm}
		if prev.Kind() != Stream {
			return nil, fmt.Errorf("malformed PDF: xref prev stream is not stream: %v", prev)
		}
		if prev.Key("Type").Name() != "XRef" {
			return nil, fmt.Errorf("malformed PDF: xref prev stream does not have type XRef")
		}
		psize := prev.Key("Size").Int64()
		if psize > size {
			return nil, fmt.Errorf("malformed PDF: xref prev stream larger than last stream")
		}
		var dataErr error
		table, dataErr = readXrefStreamData(r, prev.data.(stream), table, psize)
		if dataErr != nil {
			return nil, fmt.Errorf("malformed PDF: reading xref prev stream: %w", dataErr)
		}
		return prevstrm.hdr["Prev"], nil
	})
	if err != nil {
		return nil, objptr{}, nil, err
	}

	return table, strmptr, strm.hdr, nil
}

func readXrefStreamData(r *Reader, strm stream, table *xrefTable, size int64) (*xrefTable, error) {
	index, _ := strm.hdr["Index"].(array)
	if index == nil {
		index = array{int64(0), size}
	}
	if len(index)%2 != 0 {
		return nil, fmt.Errorf("invalid Index array %v", objfmt(index))
	}
	ww, ok := strm.hdr["W"].(array)
	if !ok {
		return nil, fmt.Errorf("xref stream missing W array")
	}

	var w []int
	for _, x := range ww {
		i, ok := x.(int64)
		if !ok || int64(int(i)) != i {
			return nil, fmt.Errorf("invalid W array %v", objfmt(ww))
		}
		// A /W entry is a field width in bytes. A negative one slices the
		// read buffer with a negative bound below, and a huge one makes
		// wtotal, and with it the buffer, arbitrarily large.
		if i < 0 || i > maxXrefFieldWidth {
			return nil, fmt.Errorf("invalid W array %v", objfmt(ww))
		}
		w = append(w, int(i))
	}
	if len(w) < 3 {
		return nil, fmt.Errorf("invalid W array %v", objfmt(ww))
	}

	v := Value{r: r, data: strm}
	wtotal := 0
	for _, wid := range w {
		wtotal += wid
	}
	if wtotal == 0 {
		return nil, fmt.Errorf("invalid W array %v: no bytes per entry", objfmt(ww))
	}
	buf := make([]byte, wtotal)
	data := v.Reader()
	for len(index) > 0 {
		start, ok1 := index[0].(int64)
		n, ok2 := index[1].(int64)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("malformed Index pair %v %v %T %T", objfmt(index[0]), objfmt(index[1]), index[0], index[1])
		}
		index = index[2:]
		// Object numbers must fit an objptr's uint32.
		if err := checkObjectNumber(start); err != nil {
			return nil, fmt.Errorf("invalid Index start: %w", err)
		}
		if err := checkObjectNumber(start + n); err != nil {
			return nil, fmt.Errorf("invalid Index range: %w", err)
		}
		for i := range n {
			if table.rows++; table.rows > maxXrefRows {
				return nil, fmt.Errorf("xref streams hold more than %d rows", maxXrefRows)
			}
			_, err := io.ReadFull(data, buf)
			if err != nil {
				return nil, fmt.Errorf("error reading xref stream: %w", err)
			}
			v1 := decodeInt(buf[0:w[0]])
			if w[0] == 0 {
				v1 = 1
			}
			v2 := decodeInt(buf[w[0] : w[0]+w[1]])
			v3 := decodeInt(buf[w[0]+w[1] : w[0]+w[1]+w[2]])
			x := uint32(start + i)
			if table.get(x).ptr != (objptr{}) {
				continue
			}
			if table.n >= maxXrefEntries {
				return nil, fmt.Errorf("xref stream holds more than %d entries", maxXrefEntries)
			}
			switch v1 {
			case 0:
				table.put(x, xref{ptr: objptr{0, 65535}})
			case 1:
				if v2 < 0 {
					return nil, fmt.Errorf("negative offset in xref stream entry %d", x)
				}
				table.put(x, xref{ptr: objptr{x, uint16(v3)}, offset: int64(v2)})
			case 2:
				table.put(x, xref{ptr: objptr{x, 0}, inStream: true, stream: objptr{uint32(v2), 0}, offset: int64(v3)})
			default:
				if DebugOn {
					fmt.Printf("invalid xref stream type %d: %x\n", v1, buf)
				}
			}
		}
	}
	return table, nil
}

func decodeInt(b []byte) int {
	x := 0
	for _, c := range b {
		x = x<<8 | int(c)
	}
	return x
}

// ensureXrefLen grows table, if needed, so that table[x] is a valid element.
// Capacity doubles but never past limit.
func ensureXrefLen(table []xref, x, limit int) []xref {
	if x < len(table) {
		return table
	}
	if x < cap(table) {
		return table[:x+1]
	}
	t := make([]xref, x+1, max(min(2*cap(table), limit), x+1))
	copy(t, table)
	return t
}

func readXrefTable(r *Reader, b *buffer) (*xrefTable, objptr, dict, error) {
	table, err := readXrefTableData(b, newXrefTable(0))
	if err != nil {
		return nil, objptr{}, nil, fmt.Errorf("malformed PDF: %w", err)
	}

	trailer, ok := b.readObject().(dict)
	if !ok {
		return nil, objptr{}, nil, fmt.Errorf("malformed PDF: xref table not followed by trailer dictionary")
	}

	err = readPrevXrefs(r, trailer["Prev"], func(b *buffer) (object, error) {
		if tok := b.readToken(); tok != keyword("xref") {
			return nil, fmt.Errorf("malformed PDF: xref Prev does not point to xref")
		}
		var dataErr error
		table, dataErr = readXrefTableData(b, table)
		if dataErr != nil {
			return nil, fmt.Errorf("malformed PDF: %w", dataErr)
		}
		prevTrailer, ok := b.readObject().(dict)
		if !ok {
			return nil, fmt.Errorf("malformed PDF: xref Prev table not followed by trailer dictionary")
		}
		return prevTrailer["Prev"], nil
	})
	if err != nil {
		return nil, objptr{}, nil, err
	}

	size, ok := trailer[name("Size")].(int64)
	if !ok {
		return nil, objptr{}, nil, fmt.Errorf("malformed PDF: trailer missing /Size entry")
	}
	// A negative /Size would panic in truncate.
	if err := checkObjectNumber(size); err != nil {
		return nil, objptr{}, nil, fmt.Errorf("malformed PDF: trailer /Size: %w", err)
	}

	table.truncate(size)

	return table, objptr{}, trailer, nil
}

func readXrefTableData(b *buffer, table *xrefTable) (*xrefTable, error) {
	for {
		tok := b.readToken()
		if tok == keyword("trailer") {
			break
		}
		start, ok1 := tok.(int64)
		n, ok2 := b.readToken().(int64)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("malformed xref table")
		}
		// Object numbers must fit an objptr's uint32.
		if err := checkObjectNumber(start); err != nil {
			return nil, fmt.Errorf("malformed xref table: %w", err)
		}
		if err := checkObjectNumber(start + n); err != nil {
			return nil, fmt.Errorf("malformed xref table: %w", err)
		}
		for i := range n {
			if table.rows++; table.rows > maxXrefRows {
				return nil, fmt.Errorf("malformed xref table: more than %d rows", maxXrefRows)
			}
			off, ok1 := b.readToken().(int64)
			gen, ok2 := b.readToken().(int64)
			alloc, ok3 := b.readToken().(keyword)
			if !ok1 || !ok2 || !ok3 || alloc != keyword("f") && alloc != keyword("n") {
				return nil, fmt.Errorf("malformed xref table")
			}
			if off < 0 {
				return nil, fmt.Errorf("malformed xref table: negative offset %d", off)
			}
			x := uint32(start + i)
			if table.n >= maxXrefEntries {
				return nil, fmt.Errorf("malformed xref table: more than %d entries", maxXrefEntries)
			}
			if alloc == "n" && table.get(x).offset == 0 {
				table.put(x, xref{ptr: objptr{x, uint16(gen)}, offset: int64(off)})
			}
		}
	}
	return table, nil
}

// validHeader reports whether buf opens with a PDF 1.0 to 1.7 or 2.x header
// line.
func validHeader(buf []byte) bool {
	if len(buf) < 9 || !bytes.HasPrefix(buf, []byte("%PDF-")) || buf[6] != '.' || buf[8] != '\r' && buf[8] != '\n' {
		return false
	}
	switch major, minor := buf[5], buf[7]; major {
	case '1':
		return minor >= '0' && minor <= '7'
	case '2':
		return minor >= '0' && minor <= '9'
	}
	return false
}

func findLastLine(buf []byte, s string) int {
	bs := []byte(s)
	max := len(buf)
	for {
		i := bytes.LastIndex(buf[:max], bs)
		if i <= 0 || i+len(bs) >= len(buf) {
			return -1
		}
		if (buf[i-1] == '\n' || buf[i-1] == '\r') && (buf[i+len(bs)] == '\n' || buf[i+len(bs)] == '\r') {
			return i
		}
		max = i
	}
}

// A Value is a single PDF value, such as an integer, dictionary, or array.
// The zero Value is a PDF null (Kind() == Null, IsNull() = true).
type Value struct {
	r    *Reader
	ptr  objptr
	data interface{}
	// viaEF marks a value reached through a file specification's /EF, so
	// that an embedded file stream with no /Type still takes /EFF.
	viaEF bool
}

// IsNull reports whether the value is a null. It is equivalent to Kind() == Null.
func (v Value) IsNull() bool {
	return v.data == nil
}

// A ValueKind specifies the kind of data underlying a Value.
type ValueKind int

// The PDF value kinds.
const (
	Null ValueKind = iota
	Bool
	Integer
	Real
	String
	Name
	Dict
	Array
	Stream
)

// Kind reports the kind of value underlying v.
func (v Value) Kind() ValueKind {
	switch v.data.(type) {
	default:
		return Null
	case bool:
		return Bool
	case int64:
		return Integer
	case float64:
		return Real
	case string:
		return String
	case name:
		return Name
	case dict:
		return Dict
	case array:
		return Array
	case stream:
		return Stream
	}
}

// String returns a textual representation of the value v.
// Note that String is not the accessor for values with Kind() == String.
// To access such values, see RawString, Text, and TextFromUTF16.
func (v Value) String() string {
	return objfmt(v.data)
}

func objfmt(x interface{}) string {
	switch x := x.(type) {
	default:
		return fmt.Sprint(x)
	case string:
		if isPDFDocEncoded(x) {
			return strconv.Quote(pdfDocDecode(x))
		}
		if isUTF16(x) {
			return strconv.Quote(utf16Decode(x[2:]))
		}
		return strconv.Quote(x)
	case name:
		return "/" + string(x)
	case dict:
		var keys []string
		for k := range x {
			keys = append(keys, string(k))
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		buf.WriteString("<<")
		for i, k := range keys {
			elem := x[name(k)]
			if i > 0 {
				buf.WriteString(" ")
			}
			buf.WriteString("/")
			buf.WriteString(k)
			buf.WriteString(" ")
			buf.WriteString(objfmt(elem))
		}
		buf.WriteString(">>")
		return buf.String()

	case array:
		var buf bytes.Buffer
		buf.WriteString("[")
		for i, elem := range x {
			if i > 0 {
				buf.WriteString(" ")
			}
			buf.WriteString(objfmt(elem))
		}
		buf.WriteString("]")
		return buf.String()

	case stream:
		return fmt.Sprintf("%v@%d", objfmt(x.hdr), x.offset)

	case objptr:
		return fmt.Sprintf("%d %d R", x.id, x.gen)

	case objdef:
		return fmt.Sprintf("{%d %d obj}%v", x.ptr.id, x.ptr.gen, objfmt(x.obj))
	}
}

// Bool returns v's boolean value.
// If v.Kind() != Bool, Bool returns false.
func (v Value) Bool() bool {
	x, ok := v.data.(bool)
	if !ok {
		return false
	}
	return x
}

// Int64 returns v's int64 value.
// If v.Kind() != Int64, Int64 returns 0.
func (v Value) Int64() int64 {
	x, ok := v.data.(int64)
	if !ok {
		return 0
	}
	return x
}

// Float64 returns v's float64 value, converting from integer if necessary.
// If v.Kind() != Float64 and v.Kind() != Int64, Float64 returns 0.
func (v Value) Float64() float64 {
	x, ok := v.data.(float64)
	if !ok {
		x, ok := v.data.(int64)
		if ok {
			return float64(x)
		}
		return 0
	}
	return x
}

// RawString returns v's string value.
// If v.Kind() != String, RawString returns the empty string.
func (v Value) RawString() string {
	x, ok := v.data.(string)
	if !ok {
		return ""
	}
	return x
}

// Text returns v's string value interpreted as a “text string” (defined in the PDF spec)
// and converted to UTF-8.
// If v.Kind() != String, Text returns the empty string.
func (v Value) Text() string {
	x, ok := v.data.(string)
	if !ok {
		return ""
	}
	if isPDFDocEncoded(x) {
		return pdfDocDecode(x)
	}
	if isUTF16(x) {
		return utf16Decode(x[2:])
	}
	return x
}

// TextFromUTF16 returns v's string value interpreted as big-endian UTF-16
// and then converted to UTF-8.
// If v.Kind() != String or if the data is not valid UTF-16, TextFromUTF16 returns
// the empty string.
func (v Value) TextFromUTF16() string {
	x, ok := v.data.(string)
	if !ok {
		return ""
	}
	if len(x)%2 == 1 {
		return ""
	}
	if x == "" {
		return ""
	}
	return utf16Decode(x)
}

// Name returns v's name value.
// If v.Kind() != Name, Name returns the empty string.
// The returned name does not include the leading slash:
// if v corresponds to the name written using the syntax /Helvetica,
// Name() == "Helvetica".
func (v Value) Name() string {
	x, ok := v.data.(name)
	if !ok {
		return ""
	}
	return string(x)
}

// Key returns the value associated with the given name key in the dictionary v.
// Like the result of the Name method, the key should not include a leading slash.
// If v is a stream, Key applies to the stream's header dictionary.
// If v.Kind() != Dict and v.Kind() != Stream, Key returns a null Value.
func (v Value) Key(key string) Value {
	x, ok := v.data.(dict)
	if !ok {
		strm, ok := v.data.(stream)
		if !ok {
			return Value{}
		}
		x = strm.hdr
	}
	res := v.r.resolve(v.ptr, x[name(key)])
	// A file specification's /EF names its embedded file streams; /Type is
	// required on one that has it.
	_, isStream := v.data.(stream)
	res.viaEF = v.viaEF && !isStream || key == "EF" && v.Key("Type").Name() == "Filespec"
	return res
}

// Keys returns a sorted list of the keys in the dictionary v.
// If v is a stream, Keys applies to the stream's header dictionary.
// If v.Kind() != Dict and v.Kind() != Stream, Keys returns nil.
func (v Value) Keys() []string {
	x, ok := v.data.(dict)
	if !ok {
		strm, ok := v.data.(stream)
		if !ok {
			return nil
		}
		x = strm.hdr
	}
	keys := []string{} // not nil
	for k := range x {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	return keys
}

// Index returns the i'th element in the array v.
// If v.Kind() != Array or if i is outside the array bounds,
// Index returns a null Value.
func (v Value) Index(i int) Value {
	x, ok := v.data.(array)
	if !ok || i < 0 || i >= len(x) {
		return Value{}
	}
	return v.r.resolve(v.ptr, x[i])
}

// Len returns the length of the array v.
// If v.Kind() != Array, Len returns 0.
func (v Value) Len() int {
	x, ok := v.data.(array)
	if !ok {
		return 0
	}
	return len(x)
}

// resolve returns x as a Value, loading it first if it is a reference. It
// recurses at most once: an object stream's header is read through a view
// that resolves nothing inside a stream.
func (r *Reader) resolve(parent objptr, x interface{}) Value {
	if ptr, ok := x.(objptr); ok {
		xref := r.xref.get(ptr.id)
		if xref.ptr != ptr || !xref.inStream && xref.offset == 0 {
			return Value{}
		}
		var obj object
		if xref.inStream {
			if r.noObjStm {
				return Value{}
			}
			x = r.objectInStream(ptr, xref.stream)
		} else {
			b := newBuffer(io.NewSectionReader(r.f, xref.offset, r.end-xref.offset), xref.offset)
			b.key = r.key
			b.crypt = r.strCrypt
			obj = b.readObject()
			r.spend(b.readOffset() - xref.offset)
			def, ok := obj.(objdef)
			if !ok {
				panic(fmt.Errorf("loading %v: found %T instead of objdef", ptr, obj))
				//return Value{}
			}
			if def.ptr != ptr {
				panic(fmt.Errorf("loading %v: found %v", ptr, def.ptr))
			}
			x = def.obj
		}
		parent = ptr
	}

	switch x := x.(type) {
	case nil, bool, int64, float64, name, dict, array, stream:
		return Value{r: r, ptr: parent, data: x}
	case string:
		return Value{r: r, ptr: parent, data: x}
	default:
		panic(fmt.Errorf("unexpected value type %T in resolve", x))
	}
}

// A readerCache holds what a Reader decodes once and reuses. A Reader and
// the views made of it share one.
type readerCache struct {
	mu      sync.Mutex
	objStms map[objptr]*cached[*objStm]
	cmaps   map[objptr]*cached[*cmap]
	fonts   map[objptr]*cached[*Font]
	cids    map[objptr]*cached[*cidMetrics]
	pages   cached[[]pageEntry]
	// indexed counts the entries every decoded object stream's index has
	// added, against maxXrefEntries.
	indexed atomic.Int64
	// budget is what remains of the limit on the bytes the Reader's
	// streams may yield.
	budget atomic.Int64
	limit  int64
	// glyphs is what remains of the limit on the glyphs text extraction
	// shows, which is otherwise bounded only per page.
	glyphs atomic.Int64
}

// A budgetReader charges what it reads against its Reader's decode budget.
type budgetReader struct {
	r io.Reader
	c *readerCache
}

func (b *budgetReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if e := b.c.spend(int64(n)); e != nil {
		return 0, e
	}
	return n, err
}

func (c *readerCache) spend(n int64) error {
	if c.budget.Add(-n) < 0 {
		return LimitError{"DecodeBudget", c.limit}
	}
	return nil
}

// spend charges n bytes against r's decode budget: those of an object parsed
// from the file, so that a large object many pages share costs each read, or
// the fixed cost of a /Contents entry.
func (r *Reader) spend(n int64) {
	if err := r.cache.spend(n); err != nil {
		panic(err)
	}
}

// charge counts what rd yields against r's decode budget.
func (r *Reader) charge(rd io.Reader) io.Reader {
	if r.cache == nil {
		return rd
	}
	return &budgetReader{rd, r.cache}
}

// A cached value is loaded once, by whichever caller asks first. A panic
// raised loading it is kept and raised again for every caller.
type cached[T any] struct {
	once sync.Once
	v    T
	err  any
}

// cacheEntry returns the entry for key in *m, adding an empty one if there is
// none.
func cacheEntry[T any](c *readerCache, m *map[objptr]*cached[T], key objptr) *cached[T] {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := (*m)[key]
	if e == nil {
		if *m == nil {
			*m = make(map[objptr]*cached[T])
		}
		e = new(cached[T])
		(*m)[key] = e
	}
	return e
}

func (e *cached[T]) get(load func() T) T {
	e.once.Do(func() {
		defer func() { e.err = recover() }()
		e.v = load()
	})
	if e.err != nil {
		panic(e.err)
	}
	return e.v
}

// An objStm is a decoded object stream.
type objStm struct {
	data    []byte
	offs    map[uint32]int // object number to offset in data
	extends objptr
	// readErr ended the read early, and scanErr the index scan; an object
	// either cut off reports it.
	readErr, scanErr error
}

// objStm returns the decoded object stream ptr, decoding it on first use.
func (r *Reader) objStm(ptr objptr) *objStm {
	return cacheEntry(r.cache, &r.cache.objStms, ptr).get(func() *objStm { return r.loadObjStm(ptr) })
}

// loadObjStm decodes object stream ptr and indexes the objects it holds.
//
// The index table declares /N pairs, but /N is a claim rather than a
// measurement: the end of the table ends the scan, and a pair the file got
// wrong is skipped so that the ones after it still resolve.
func (r *Reader) loadObjStm(ptr objptr) *objStm {
	view := *r
	view.noObjStm = true
	strm := view.resolve(objptr{}, ptr)
	if strm.Kind() != Stream {
		panic("not a stream")
	}
	if strm.Key("Type").Name() != "ObjStm" {
		panic("not an object stream")
	}
	n := strm.Key("N").Int64()
	first := strm.Key("First").Int64()
	if first == 0 {
		panic("missing First")
	}
	if first < 0 {
		panic(fmt.Errorf("malformed PDF: object stream /First %d", first))
	}
	s := &objStm{offs: make(map[uint32]int)}
	if ext := strm.Key("Extends"); ext.Kind() == Stream {
		s.extends = ext.ptr
	}
	s.data, s.readErr = io.ReadAll(newLimitedReader(strm.Reader(), maxObjStmBytes))
	s.index(r, n, first)
	return s
}

// index records where each object listed in the first n pairs of the
// stream's index table begins.
func (s *objStm) index(r *Reader, n, first int64) {
	defer func() {
		if x := recover(); x != nil {
			if _, ok := x.(runtime.Error); ok {
				panic(x)
			}
			s.scanErr = recoveredError(x)
		}
	}()
	b := newBuffer(bytes.NewReader(s.data), 0)
	b.allowEOF = true
	for i := int64(0); i < n && b.readOffset() < first; i++ {
		tok1, tok2 := b.readToken(), b.readToken()
		if tok1 == io.EOF || tok2 == io.EOF {
			break
		}
		id, ok1 := tok1.(int64)
		off, ok2 := tok2.(int64)
		if !ok1 || !ok2 || off < 0 || int64(uint32(id)) != id {
			continue
		}
		// Only numbers the xref places in a stream are ever looked up here,
		// though one it places in another stream may be, through /Extends.
		if _, ok := s.offs[uint32(id)]; ok || !r.xref.get(uint32(id)).inStream {
			continue
		}
		if r.cache.indexed.Add(1) > maxXrefEntries {
			panic(fmt.Errorf("object streams index more than %d objects", maxXrefEntries))
		}
		pos := int64(len(s.data))
		if first < pos && off < pos {
			pos = min(first+off, pos)
		}
		s.offs[uint32(id)] = int(pos)
	}
}

// objectInStream reads object ptr out of object stream strm, or a stream
// that strm extends.
func (r *Reader) objectInStream(ptr objptr, strm objptr) object {
	for extends := 0; ; extends++ {
		// /Extends is an object reference and can point back into the
		// chain, so cap its length rather than following it forever.
		if extends >= maxObjStmExtends {
			panic("object stream /Extends chain too long")
		}
		s := r.objStm(strm)
		off, ok := s.offs[ptr.id]
		if ok && off >= len(s.data) {
			if s.readErr != nil {
				panic(s.readErr)
			}
			panic(fmt.Errorf("object %d lies past the end of its object stream", ptr.id))
		}
		if ok {
			var rd io.Reader = bytes.NewReader(s.data[off:])
			if s.readErr != nil {
				rd = io.MultiReader(rd, &errorReadCloser{s.readErr})
			}
			b := newBuffer(rd, int64(off))
			b.allowEOF = true
			obj := b.readObject()
			r.spend(b.readOffset() - int64(off))
			return obj
		}
		if err := cmp.Or(s.readErr, s.scanErr); err != nil {
			panic(err)
		}
		if s.extends == (objptr{}) {
			panic("cannot find object in stream")
		}
		strm = s.extends
	}
}

// A limitedReader fails once more than max bytes have been read from r, where
// io.LimitReader would end quietly and truncated data would read as shorter.
type limitedReader struct {
	r      io.Reader
	n, max int64
	err    error // reported past max, if not the generic error
}

func newLimitedReader(r io.Reader, max int64) *limitedReader {
	return &limitedReader{r: r, n: max, max: max}
}

func (l *limitedReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	if l.n -= int64(n); l.n < 0 {
		if l.err != nil {
			return 0, l.err
		}
		return 0, fmt.Errorf("stream exceeds %d bytes", l.max)
	}
	return n, err
}

type errorReadCloser struct {
	err error
}

func (e *errorReadCloser) Read([]byte) (int, error) {
	return 0, e.err
}

func (e *errorReadCloser) Close() error {
	return e.err
}

// errStreamNotPresent is the error a Reader for a non-stream Value responds
// with; the lexer treats it as end of input rather than malformed data.
var errStreamNotPresent = errors.New("stream not present")

// Reader returns the data contained in the stream v.
// If v.Kind() != Stream, Reader returns a ReadCloser that
// responds to all reads with a “stream not present” error.
// A negative /Length reads as no data; io.NewSectionReader would otherwise
// take it as unbounded and read to the end of the file.
func (v Value) Reader() io.ReadCloser {
	x, ok := v.data.(stream)
	if !ok {
		return &errorReadCloser{errStreamNotPresent}
	}
	streamLen := v.Key("Length").Int64()
	// Handle empty streams - return empty reader without applying filters.
	// This avoids zlib "unexpected EOF" errors on 0-length FlateDecode streams.
	if streamLen <= 0 {
		return io.NopCloser(bytes.NewReader(nil))
	}
	filter := v.Key("Filter")
	param := v.Key("DecodeParms")
	var filters []string
	var params []Value
	switch filter.Kind() {
	default:
		panic(fmt.Errorf("unsupported filter %v", filter))
	case Null:
		// ok
	case Name:
		filters, params = []string{filter.Name()}, []Value{param}
	case Array:
		if filter.Len() > maxFilters {
			panic(fmt.Errorf("stream has %d filters, more than %d", filter.Len(), maxFilters))
		}
		for i := 0; i < filter.Len(); i++ {
			filters, params = append(filters, filter.Index(i).Name()), append(params, param.Index(i))
		}
	}

	m := v.r.stmCrypt
	switch typ := v.Key("Type").Name(); {
	case v.viaEF || typ == "EmbeddedFile":
		if v.r.effErr != nil {
			return &errorReadCloser{v.r.effErr}
		}
		m = v.r.effCrypt
	case typ == "Metadata" && v.r.clearMetadata:
		m = cryptNone
	}
	// A /Crypt filter, first in the chain, picks the stream's own crypt
	// filter by name (section 7.4.10).
	if len(filters) > 0 && filters[0] == "Crypt" {
		n := name(params[0].Key("Name").Name())
		if n == "" {
			n = "Identity"
		}
		var ok bool
		if m, ok = v.r.filters[n]; !ok && n != "Identity" {
			return &errorReadCloser{fmt.Errorf("unknown crypt filter %v", n)}
		}
		filters, params = filters[1:], params[1:]
	}
	var rd io.Reader
	rd = io.NewSectionReader(v.r.f, x.offset, streamLen)
	if m != cryptNone {
		if v.r.key == nil {
			return &errorReadCloser{v.r.keyErr}
		}
		rd = decryptStream(v.r.key, m, x.ptr, rd)
	}
	rd = v.r.charge(rd)
	for i, f := range filters {
		rd = v.r.charge(v.r.applyFilter(rd, f, params[i]))
	}

	return io.NopCloser(rd)
}

func (r *Reader) applyFilter(rd io.Reader, name string, param Value) io.Reader {
	switch name {
	default:
		panic("unknown filter " + name)
	case "FlateDecode":
		// The Adler-32 trailer goes unread, as in other readers: some writers
		// get it wrong or drop it after complete data.
		var hdr [2]byte
		if _, err := io.ReadFull(rd, hdr[:]); err != nil {
			panic(err)
		}
		if hdr[0]&0x0f != 8 || binary.BigEndian.Uint16(hdr[:])%31 != 0 || hdr[1]&0x20 != 0 {
			panic(zlib.ErrHeader)
		}
		zr := flate.NewReader(rd)
		pred := param.Key("Predictor")
		if pred.Kind() == Null {
			return zr
		}
		// The inflate beneath a predictor is a stage of its own.
		zrc := r.charge(zr)
		columns := int64(1)
		if c := param.Key("Columns"); c.Kind() != Null {
			columns = c.Int64()
		}
		// /Columns sizes the two row buffers below. A negative value panics in
		// make, a large one allocates without bound, and zero reads rows that
		// yield nothing. Xref streams are routinely FlateDecode/Predictor 12,
		// so this is reached while merely opening a file.
		if columns < 1 || columns > maxPredictorColumns {
			panic(fmt.Errorf("invalid FlateDecode /Columns %d", columns))
		}
		switch pred.Int64() {
		default:
			if DebugOn {
				fmt.Println("unknown predictor", pred)
			}
			panic("pred")
		case 12:
			return &pngUpReader{r: zrc, hist: make([]byte, 1+columns), tmp: make([]byte, 1+columns)}
		}
	case "ASCII85Decode":
		cleanASCII85 := newAlphaReader(rd)
		decoder := ascii85.NewDecoder(cleanASCII85)

		switch param.Keys() {
		default:
			if DebugOn {
				fmt.Println("param=", param)
			}
			panic("not expected DecodeParms for ascii85")
		case nil:
			return decoder
		}
	}
}

type pngUpReader struct {
	r    io.Reader
	hist []byte
	tmp  []byte
	pend []byte
}

func (r *pngUpReader) Read(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		if len(r.pend) > 0 {
			m := copy(b, r.pend)
			n += m
			b = b[m:]
			r.pend = r.pend[m:]
			continue
		}
		_, err := io.ReadFull(r.r, r.tmp)
		if err != nil {
			return n, err
		}
		if r.tmp[0] != 2 {
			return n, fmt.Errorf("malformed PNG-Up encoding")
		}
		for i, b := range r.tmp {
			r.hist[i] += b
		}
		r.pend = r.hist[1:]
	}
	return n, nil
}

var passwordPad = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

// PDF encryption parameters. See PDF 32000-1:2008, section 7.6.
const (
	// minKeyBits and maxKeyBits bound the /Length value (in bits) in the
	// encryption dictionary.
	minKeyBits = 40
	maxKeyBits = 128

	// ouEntryLen is the byte length of the O and U entries for encryption
	// revisions 2 through 4.
	ouEntryLen = 32

	// md5KeyIterations is the number of times revisions >= 3 rehash the MD5
	// that keys a file or its owner password (Algorithm 2 step f, Algorithm 3
	// step c).
	md5KeyIterations = 50

	// rc4UIterations is the number of RC4 passes, after the first, that
	// revisions >= 3 run over U and O (Algorithms 5 and 7).
	rc4UIterations = 19

	// AES-256 (V 5) parameters. See ISO 32000-2:2020, section 7.6.4.
	// aes256OULen is the byte length of O and U: a 32-byte hash, an 8-byte
	// validation salt, and an 8-byte key salt.
	aes256OULen = 48
	// aes256KeyLen is the file key's byte length, and that of OE and UE,
	// which hold it encrypted.
	aes256KeyLen = 32
	// aes256MaxPassword is the most bytes of a password that count.
	aes256MaxPassword = 127
)

// cryptMethod is how a class of strings or streams is encrypted.
type cryptMethod uint8

const (
	cryptNone cryptMethod = iota // the Identity filter: in the clear
	cryptRC4
	cryptAESV2
	cryptAESV3 // AES-256, under the file key itself
)

// errKeyless reports a file whose strings and streams are in the clear but
// whose password did not open its key, so its encrypted attachments fail to
// read.
var errKeyless = errors.New("encrypted PDF: only its attachments need a password")

func (r *Reader) initEncrypt(password string) error {
	// See PDF 32000-1:2008, section 7.6.
	encrypt, ok := r.resolve(objptr{}, r.trailer["Encrypt"]).data.(dict)
	if !ok {
		// pdf.js and qpdf read a file whose /Encrypt is no dictionary, a
		// dangling reference included, as unencrypted.
		return nil
	}
	encrypt = r.resolvedDict(encrypt)
	switch f, ok := encrypt["Filter"].(name); {
	case !ok:
		return fmt.Errorf("malformed PDF: encryption /Filter %v", objfmt(encrypt["Filter"]))
	case f != "Standard":
		return fmt.Errorf("%w %v", ErrSecurityHandler, objfmt(f))
	}
	V, _ := encrypt["V"].(int64)
	if V != 1 && V != 2 && V != 4 && V != 5 {
		return fmt.Errorf("unsupported PDF: encryption version V=%d; %v", V, objfmt(encrypt))
	}
	str, stm, eff, filters, effErr, err := r.cryptFilters(encrypt, V)
	if err != nil {
		return err
	}
	R, _ := encrypt["R"].(int64)
	clearMetadata := R >= 4 && encrypt["EncryptMetadata"] == false
	var key []byte
	if V == 5 {
		key, err = aes256FileKey(encrypt, R, password)
	} else {
		key, err = r.rc4FileKey(encrypt, V, R, clearMetadata, password)
	}
	r.key, r.keyErr = key, nil
	r.strCrypt, r.stmCrypt, r.effCrypt, r.filters, r.effErr = str, stm, eff, filters, effErr
	r.clearMetadata = clearMetadata
	if err != nil {
		// A document whose strings and streams are in the clear opens without
		// its key; only the reads that need one fail.
		if str != cryptNone || stm != cryptNone {
			return err
		}
		r.keyErr = err
		if err == ErrInvalidPassword {
			return errKeyless
		}
	}
	return nil
}

// resolvedDict returns d with each value resolved, since any may be an
// indirect reference.
func (r *Reader) resolvedDict(d dict) dict {
	out := make(dict, len(d))
	for k, x := range d {
		out[k] = r.resolve(objptr{}, x).data
	}
	return out
}

// cryptFilters returns the methods strings, streams, and embedded files are
// encrypted with, and the crypt filters by name for a stream's own /Crypt
// filter (section 7.6.5). An /EFF naming no usable filter fails only the
// attachments, through effErr.
func (r *Reader) cryptFilters(encrypt dict, V int64) (str, stm, eff cryptMethod, filters map[name]cryptMethod, effErr, err error) {
	if V < 4 {
		return cryptRC4, cryptRC4, cryptRC4, nil, nil, nil
	}
	filters = map[name]cryptMethod{"Identity": cryptNone}
	cf, _ := encrypt["CF"].(dict)
	for n, x := range cf {
		// An entry no stream may name fails nothing.
		func() {
			defer func() { _ = recover() }()
			param, _ := r.resolve(objptr{}, x).data.(dict)
			if m, ok := cryptFilterMethod(r.resolvedDict(param), V); ok && n != "Identity" {
				filters[n] = m
			}
		}()
	}
	pick := func(key, def name) (cryptMethod, error) {
		n := def
		if x := encrypt[key]; x != nil {
			var ok bool
			if n, ok = x.(name); !ok {
				return 0, fmt.Errorf("unsupported PDF: /%s %v", key, objfmt(x))
			}
		}
		m, ok := filters[n]
		if !ok {
			return 0, fmt.Errorf("unsupported PDF: crypt filter %v for %s; %v", n, key, objfmt(encrypt))
		}
		return m, nil
	}
	if str, err = pick("StrF", "Identity"); err != nil {
		return
	}
	if stm, err = pick("StmF", "Identity"); err != nil {
		return
	}
	stmName, ok := encrypt["StmF"].(name)
	if !ok {
		stmName = "Identity"
	}
	eff, effErr = pick("EFF", stmName)
	return
}

// cryptFilterMethod returns the method of a crypt filter dictionary, if a
// V4 or V5 file may use it: V4 takes RC4 (V2) and AES-128 (AESV2) under a
// 128-bit key, V5 AES-256 (AESV3).
func cryptFilterMethod(param dict, V int64) (cryptMethod, bool) {
	// EFOpen asks for the password when an attachment opens; the key is the
	// same.
	if a := param["AuthEvent"]; a != nil && a != name("DocOpen") && a != name("EFOpen") {
		return 0, false
	}
	keyLen := int64(maxKeyBits / 8)
	if V == 5 {
		keyLen = aes256KeyLen
	}
	// Writers give the key length in bytes or in bits.
	if l := param["Length"]; l != nil && l != keyLen && l != keyLen*8 {
		return 0, false
	}
	switch cfm := param["CFM"]; {
	case V == 4 && cfm == name("V2"):
		return cryptRC4, true
	case V == 4 && cfm == name("AESV2"):
		return cryptAESV2, true
	case V == 5 && cfm == name("AESV3"):
		return cryptAESV3, true
	}
	return 0, false
}

// passwordBytes lists the byte strings password may have been hashed as,
// most likely first. Revisions 2 to 4 hash PDFDocEncoding and revisions 5
// and 6 SASLprep'd UTF-8 cut to 127 bytes; some writers hash the UTF-8 as
// typed instead.
func passwordBytes(password string, R int64) [][]byte {
	raw := []byte(password)
	want := raw
	if R >= 5 {
		want = []byte(saslPrep(password))
		raw, want = raw[:min(len(raw), aes256MaxPassword)], want[:min(len(want), aes256MaxPassword)]
	} else if b, ok := pdfDocBytes(password); ok {
		want = b
	}
	if bytes.Equal(want, raw) {
		return [][]byte{want}
	}
	return [][]byte{want, raw}
}

// pdfDocBytes encodes s in PDFDocEncoding, reporting false if a rune has no
// byte there.
func pdfDocBytes(s string) ([]byte, bool) {
	b := make([]byte, 0, len(s))
	for _, c := range s {
		i := slices.Index(pdfDocEncoding[:], c)
		if i < 0 || c == noRune {
			return nil, false
		}
		b = append(b, byte(i))
	}
	return b, true
}

// saslPrep maps a password as RFC 4013 does before it is hashed: non-ASCII
// spaces become spaces, characters commonly mapped to nothing go, and the
// rest is NFKC-normalized. Its prohibitions are skipped, since a writer
// refuses such a password, so it never matches anyway. The mapping removes
// every U+034F, so any left after norm are the ones its stream-safe form
// inserts past 30 combining marks, which plain NFKC does not.
func saslPrep(s string) string {
	return strings.ReplaceAll(norm.NFKC.String(strings.Map(func(c rune) rune {
		switch c {
		case 0x00A0, 0x1680, 0x202F, 0x205F, 0x3000: // RFC 3454 table C.1.2
			return ' '
		case 0x00AD, 0x034F, 0x1806, 0x200C, 0x200D, 0x2060, 0xFEFF: // table B.1
			return -1
		}
		switch {
		case c >= 0x2000 && c <= 0x200B: // C.1.2
			return ' '
		case c >= 0x180B && c <= 0x180D, c >= 0xFE00 && c <= 0xFE0F: // B.1
			return -1
		}
		return c
	}, s)), "\u034f", "")
}

// rc4FileKey derives the file key of a V1 to V4 file, trying password as the
// user password and then as the owner password (Algorithms 2, 6, and 7).
func (r *Reader) rc4FileKey(encrypt dict, V, R int64, clearMetadata bool, password string) ([]byte, error) {
	n, _ := encrypt["Length"].(int64)
	if n == 0 {
		n = minKeyBits
	}
	if V == 4 {
		// cryptFilterMethod allows only 128-bit crypt filters, whatever
		// /Length says, and a shorter key fails aes.NewCipher.
		n = maxKeyBits
	}
	if n%8 != 0 || n > maxKeyBits || n < minKeyBits {
		return nil, fmt.Errorf("malformed PDF: %d-bit encryption key", n)
	}
	ids, ok := r.trailer["ID"].(array)
	if !ok || len(ids) < 1 {
		return nil, fmt.Errorf("malformed PDF: missing ID in trailer")
	}
	idstr, ok := ids[0].(string)
	if !ok {
		return nil, fmt.Errorf("malformed PDF: missing ID in trailer")
	}
	if R < 2 || V == 4 && R < 4 {
		return nil, fmt.Errorf("malformed PDF: encryption revision R=%d for V=%d", R, V)
	}
	if R > 4 {
		return nil, fmt.Errorf("unsupported PDF: encryption revision R=%d", R)
	}
	O, _ := encrypt["O"].(string)
	U, _ := encrypt["U"].(string)
	if len(O) != ouEntryLen || len(U) != ouEntryLen {
		return nil, fmt.Errorf("malformed PDF: missing O= or U= encryption parameters")
	}
	p, _ := encrypt["P"].(int64)
	s := rc4Params{R: R, keyLen: int(n / 8), O: []byte(O), U: []byte(U), ID: []byte(idstr), P: uint32(p), clearMetadata: clearMetadata}
	if R == 2 {
		s.keyLen = minKeyBits / 8
	}
	for _, pw := range passwordBytes(password, R) {
		if key, ok := s.userKey(pw); ok {
			return key, nil
		}
		if key, ok := s.userKey(s.ownerToUser(pw)); ok {
			return key, nil
		}
	}
	return nil, ErrInvalidPassword
}

// rc4Params are a V1 to V4 file's Standard security handler entries.
type rc4Params struct {
	R             int64
	keyLen        int
	O, U, ID      []byte
	P             uint32
	clearMetadata bool
}

// padPassword pads or cuts pw to 32 bytes (Algorithm 2, step a).
func padPassword(pw []byte) []byte {
	return append(slices.Clone(pw[:min(len(pw), len(passwordPad))]), passwordPad[:len(passwordPad)-min(len(pw), len(passwordPad))]...)
}

// userKey derives the file key from pw as the user password and checks it
// against U (Algorithms 2, 4, and 5).
func (s rc4Params) userKey(pw []byte) ([]byte, bool) {
	h := md5.New()
	h.Write(padPassword(pw))
	h.Write(s.O)
	h.Write([]byte{byte(s.P), byte(s.P >> 8), byte(s.P >> 16), byte(s.P >> 24)})
	h.Write(s.ID)
	if s.clearMetadata {
		h.Write([]byte{0xff, 0xff, 0xff, 0xff})
	}
	key := h.Sum(nil)
	if s.R >= 3 {
		for range md5KeyIterations {
			sum := md5.Sum(key[:s.keyLen])
			key = sum[:]
		}
	}
	key = key[:s.keyLen]

	var u []byte
	if s.R == 2 {
		u = slices.Clone(passwordPad)
		c, _ := rc4.NewCipher(key)
		c.XORKeyStream(u, u)
	} else {
		sum := md5.Sum(slices.Concat(passwordPad, s.ID))
		u = sum[:]
		for i := 0; i <= rc4UIterations; i++ {
			c, _ := rc4.NewCipher(xorKey(key, byte(i)))
			c.XORKeyStream(u, u)
		}
	}
	return key, bytes.HasPrefix(s.U, u)
}

// ownerToUser recovers the padded user password from O with pw as the owner
// password (Algorithm 7, through Algorithm 3's key).
func (s rc4Params) ownerToUser(pw []byte) []byte {
	sum := md5.Sum(padPassword(pw))
	key := sum[:]
	if s.R >= 3 {
		for range md5KeyIterations {
			sum = md5.Sum(key)
			key = sum[:]
		}
	}
	key = key[:s.keyLen]
	u := slices.Clone(s.O)
	if s.R == 2 {
		c, _ := rc4.NewCipher(key)
		c.XORKeyStream(u, u)
		return u
	}
	for i := rc4UIterations; i >= 0; i-- {
		c, _ := rc4.NewCipher(xorKey(key, byte(i)))
		c.XORKeyStream(u, u)
	}
	return u
}

// xorKey returns key with every byte XORed with i.
func xorKey(key []byte, i byte) []byte {
	k := slices.Clone(key)
	for j := range k {
		k[j] ^= i
	}
	return k
}

// aes256FileKey derives the file key of an AES-256 file, trying password as
// the user password and then as the owner password (ISO 32000-2:2020,
// Algorithm 2.A).
func aes256FileKey(encrypt dict, R int64, password string) ([]byte, error) {
	if R < 5 {
		return nil, fmt.Errorf("malformed PDF: encryption revision R=%d", R)
	}
	if R > 6 {
		return nil, fmt.Errorf("unsupported PDF: encryption revision R=%d", R)
	}
	// Viewers read the first bytes of a longer entry, so only a short one is
	// malformed.
	O, _ := encrypt["O"].(string)
	U, _ := encrypt["U"].(string)
	OE, _ := encrypt["OE"].(string)
	UE, _ := encrypt["UE"].(string)
	if len(O) < aes256OULen || len(U) < aes256OULen || len(OE) < aes256KeyLen || len(UE) < aes256KeyLen {
		return nil, fmt.Errorf("malformed PDF: missing O=, U=, OE=, or UE= encryption parameters")
	}
	u := []byte(U[:aes256OULen])
	for _, pw := range passwordBytes(password, R) {
		// The owner's hashes take U as well.
		for _, k := range []struct {
			entry, encKey, udata []byte
		}{
			{u, []byte(UE[:aes256KeyLen]), nil},
			{[]byte(O[:aes256OULen]), []byte(OE[:aes256KeyLen]), u},
		} {
			hash, validationSalt, keySalt := k.entry[:32], k.entry[32:40], k.entry[40:48]
			if !bytes.Equal(aes256Hash(R, pw, validationSalt, k.udata), hash) {
				continue
			}
			b, err := aes.NewCipher(aes256Hash(R, pw, keySalt, k.udata))
			if err != nil {
				return nil, fmt.Errorf("malformed PDF: invalid AES key: %w", err)
			}
			key := slices.Clone(k.encKey)
			cipher.NewCBCDecrypter(b, make([]byte, aes.BlockSize)).CryptBlocks(key, key)
			return key, nil
		}
	}
	return nil, ErrInvalidPassword
}

// aes256Hash hashes a password with salt and, for the owner, U (ISO
// 32000-2:2020, Algorithm 2.B). Revision 5 stops at the first SHA-256.
// Revision 6 runs at least 64 rounds and stops once E's last byte is at most
// the round count less 32, so by round 287 at the latest.
func aes256Hash(R int64, pw, salt, udata []byte) []byte {
	sum := sha256.Sum256(slices.Concat(pw, salt, udata))
	k := sum[:]
	if R == 5 {
		return k
	}
	var e []byte
	for i := 0; i < 64 || int(e[len(e)-1]) > i-32; i++ {
		e = e[:0]
		for range 64 {
			e = append(append(append(e, pw...), k...), udata...)
		}
		b, _ := aes.NewCipher(k[:16])
		cipher.NewCBCEncrypter(b, k[16:32]).CryptBlocks(e, e)
		// The first 16 bytes of E, big-endian, modulo 3; 256 is 1 modulo 3,
		// so their sum gives the same remainder.
		n := 0
		for _, c := range e[:16] {
			n += int(c)
		}
		switch n % 3 {
		case 0:
			s := sha256.Sum256(e)
			k = s[:]
		case 1:
			s := sha512.Sum384(e)
			k = s[:]
		default:
			s := sha512.Sum512(e)
			k = s[:]
		}
	}
	return k[:32]
}

var ErrInvalidPassword = fmt.Errorf("encrypted PDF: invalid password")

// ErrSecurityHandler is a file encrypted by a handler other than the Standard
// one, such as to public-key certificates, which no password opens.
var ErrSecurityHandler = errors.New("unsupported PDF: encryption filter")

// cryptKey derives an object's key from the file key (Algorithm 1), except
// under AES-256, which encrypts every object with the file key itself.
func cryptKey(key []byte, m cryptMethod, ptr objptr) []byte {
	if m == cryptAESV3 {
		return key
	}
	h := md5.New()
	h.Write(key)
	h.Write([]byte{byte(ptr.id), byte(ptr.id >> 8), byte(ptr.id >> 16), byte(ptr.gen), byte(ptr.gen >> 8)})
	if m == cryptAESV2 {
		h.Write([]byte("sAlT"))
	}
	return h.Sum(nil)[:min(len(key)+5, md5.Size)]
}

// A stringDecrypter decrypts the strings of an object, deriving its key and
// cipher once rather than per string: an object can hold millions.
type stringDecrypter struct {
	ptr   objptr
	block cipher.Block
	rc4   *rc4.Cipher
	ks    []byte // the RC4 keystream, as long as the longest string so far
}

func (d *stringDecrypter) decrypt(key []byte, m cryptMethod, ptr objptr, x string) string {
	useAES := m != cryptRC4
	if d.ptr != ptr || d.block == nil && d.rc4 == nil {
		*d = stringDecrypter{ptr: ptr}
		key = cryptKey(key, m, ptr)
		if useAES {
			d.block, _ = aes.NewCipher(key)
		} else {
			d.rc4, _ = rc4.NewCipher(key)
		}
	}
	if useAES {
		// Anything shorter than an IV and one block holds no text.
		if len(x) < 2*aes.BlockSize {
			return ""
		}
		// CBC by hand, last block first so that each one's predecessor is
		// still ciphertext: a BlockMode per string copies the expanded key.
		s := []byte(x[:len(x)-len(x)%aes.BlockSize])
		for i := len(s) - aes.BlockSize; i >= aes.BlockSize; i -= aes.BlockSize {
			blk := s[i : i+aes.BlockSize]
			d.block.Decrypt(blk, blk)
			subtle.XORBytes(blk, blk, s[i-aes.BlockSize:i])
		}
		return string(unpad(s[aes.BlockSize:]))
	}
	// Each string is encrypted from the start of the keystream.
	if n := len(x) - len(d.ks); n > 0 {
		d.ks = append(d.ks, make([]byte, n)...)
		d.rc4.XORKeyStream(d.ks[len(d.ks)-n:], d.ks[len(d.ks)-n:])
	}
	s := []byte(x)
	subtle.XORBytes(s, s, d.ks)
	return string(s)
}

// unpad strips the PKCS#7 padding that AES encryption appends, leaving
// data that does not end in a padding length as it is.
func unpad(b []byte) []byte {
	if n := len(b); n > 0 {
		if p := int(b[n-1]); p >= 1 && p <= aes.BlockSize && p <= n {
			return b[:n-p]
		}
	}
	return b
}

func decryptStream(key []byte, m cryptMethod, ptr objptr, rd io.Reader) io.Reader {
	key = cryptKey(key, m, ptr)
	if m != cryptRC4 {
		cb, err := aes.NewCipher(key)
		if err != nil {
			panic("AES: " + err.Error())
		}
		iv := make([]byte, 16)
		io.ReadFull(rd, iv)
		rd = &cbcReader{cbc: cipher.NewCBCDecrypter(cb, iv), rd: rd}
	} else {
		c, _ := rc4.NewCipher(key)
		rd = &cipher.StreamReader{S: c, R: rd}
	}
	return rd
}

// A cbcReader decrypts AES-CBC data. It holds the last whole block back
// until the data ends, so that the padding there can be stripped, and drops
// a partial block at the end, since /Length can run a few bytes past the
// data.
type cbcReader struct {
	cbc  cipher.BlockMode
	rd   io.Reader
	buf  []byte
	held []byte // ciphertext not yet decrypted, at the end of buf's last fill
	pend []byte // plaintext not yet returned
	err  error
}

func (r *cbcReader) Read(b []byte) (int, error) {
	for len(r.pend) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.buf == nil {
			// Allocated on first read: callers can open many streams before
			// reading any.
			r.buf = make([]byte, 4096)
		}
		n := copy(r.buf, r.held)
		m, err := io.ReadFull(r.rd, r.buf[n:])
		n += m
		switch err {
		case nil:
			k := n - aes.BlockSize
			r.cbc.CryptBlocks(r.buf[:k], r.buf[:k])
			r.pend, r.held = r.buf[:k], r.buf[k:n]
		case io.EOF, io.ErrUnexpectedEOF:
			k := n - n%aes.BlockSize
			r.cbc.CryptBlocks(r.buf[:k], r.buf[:k])
			r.pend, r.held, r.err = unpad(r.buf[:k]), nil, io.EOF
		default:
			r.err = err
		}
	}
	n := copy(b, r.pend)
	r.pend = r.pend[n:]
	return n, nil
}
