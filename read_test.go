package pdf

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadObjectMaxDepth(t *testing.T) {
	// Craft a payload of deeply nested "0 0 obj" sequences that would
	// previously cause unbounded recursion and a fatal stack overflow.
	// With the depth limit in place this must produce a recoverable panic
	// (caught here) instead of crashing the process.
	const depth = maxObjectDepth + 100
	var payload bytes.Buffer
	for i := 0; i < depth; i++ {
		payload.WriteString("0 0 obj\n")
	}

	b := newBuffer(&payload, 0)
	b.allowEOF = true

	panicked := false
	var panicMsg string
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicMsg = r.(error).Error()
			}
		}()
		b.readObject()
	}()

	if !panicked {
		t.Fatal("expected panic from deeply nested objects, but readObject returned normally")
	}
	if !strings.Contains(panicMsg, "maximum depth") {
		t.Fatalf("expected 'maximum depth' in panic message, got: %s", panicMsg)
	}
}

// TestObjectDepthRefuses verifies that an object nesting past the depth cap
// refuses the file as a LimitError: a page holding one in a strict open, and
// a font holding one in Page.Content.
func TestObjectDepthRefuses(t *testing.T) {
	nest := strings.Repeat("[", maxObjectDepth+1) + strings.Repeat("]", maxObjectDepth+1)
	isDepth := func(err error) bool {
		var le LimitError
		return errors.As(err, &le) && le.Limit == "ObjectDepth" && le.Max == maxObjectDepth
	}
	data := pagePDF("/Junk "+nest, flateObj("BT (x) Tj ET"))
	if _, err := NewReaderOptions(bytes.NewReader(data), int64(len(data)), Options{}); !isDepth(err) {
		t.Errorf("NewReaderOptions: err %v, want the object depth cap", err)
	}
	data = pagePDF("/Resources << /Font << /F1 5 0 R >> >>", flateObj("BT /F1 12 Tf (x) Tj ET"), "<< /Subtype /Type1 /Junk "+nest+" >>")
	p := openPDF(t, data).Page(1)
	var err error
	func() {
		defer func() { err, _ = recover().(error) }()
		p.Content()
	}()
	if !isDepth(err) {
		t.Errorf("Content panicked with %v, want the object depth cap", err)
	}
}

func TestReadDictMaxDepth(t *testing.T) {
	// Deeply nested dictionaries: << /A << /A << ... >> >> >>
	var payload bytes.Buffer
	const depth = maxObjectDepth + 100
	for i := 0; i < depth; i++ {
		payload.WriteString("<< /A ")
	}
	payload.WriteString("null")
	for i := 0; i < depth; i++ {
		payload.WriteString(" >>")
	}

	b := newBuffer(&payload, 0)
	b.allowEOF = true

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		b.readObject()
	}()

	if !panicked {
		t.Fatal("expected panic from deeply nested dicts, but readObject returned normally")
	}
}

func TestReadArrayMaxDepth(t *testing.T) {
	// Deeply nested arrays: [ [ [ ... ] ] ]
	var payload bytes.Buffer
	const depth = maxObjectDepth + 100
	for i := 0; i < depth; i++ {
		payload.WriteString("[ ")
	}
	payload.WriteString("null")
	for i := 0; i < depth; i++ {
		payload.WriteString(" ]")
	}

	b := newBuffer(&payload, 0)
	b.allowEOF = true

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		b.readObject()
	}()

	if !panicked {
		t.Fatal("expected panic from deeply nested arrays, but readObject returned normally")
	}
}

func TestReadObjectNormalDepth(t *testing.T) {
	// A moderately nested structure should parse without hitting the limit.
	var payload bytes.Buffer
	const depth = 50
	for i := 0; i < depth; i++ {
		payload.WriteString("<< /A ")
	}
	payload.WriteString("(hello)")
	for i := 0; i < depth; i++ {
		payload.WriteString(" >>")
	}

	b := newBuffer(&payload, 0)
	b.allowEOF = true

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		obj := b.readObject()
		if obj == nil {
			t.Fatal("expected non-nil object from moderately nested dict")
		}
	}()

	if panicked {
		t.Fatal("unexpected panic from moderately nested dicts")
	}
}

func TestNewReaderMaliciousPDF(t *testing.T) {
	// Reproduce the exact attack vector from MM-63434: a PDF with millions
	// of "0 0 obj" tokens that triggers deep recursion during NewReader's
	// xref parsing. With the fix, NewReader should return an error (via
	// recovered panic) rather than crashing the process.
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.0\n")
	for i := 0; i < 10_000; i++ {
		pdf.WriteString("0\n0\nobj\n")
	}
	pdf.WriteString("startxref\n0\n%%EOF\n")

	data := pdf.Bytes()
	_, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err == nil {
		t.Fatal("expected error from malicious PDF, got nil")
	}
}

// TestMissingContentStreamDoesNotPanic verifies that a page whose /Contents
// points at an object with no stream data degrades to an empty page instead
// of panicking out of Page.Content and text extraction. Value.Reader responds
// to reads on such objects with errStreamNotPresent, which the lexer treats
// as end of input.
func TestMissingContentStreamDoesNotPanic(t *testing.T) {
	pdfData := buildPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 4 0 R >>",
		"<< /Length 0 >>",
	)
	reader, err := NewReader(bytes.NewReader(pdfData), int64(len(pdfData)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on a page without a content stream: %v", r)
		}
	}()

	content := reader.Page(1).Content()
	if len(content.Text) != 0 {
		t.Fatalf("expected no text, got %v", content.Text)
	}

	text, err := reader.Page(1).GetPlainText(nil)
	if err != nil {
		t.Fatalf("GetPlainText: %v", err)
	}
	if text != "" {
		t.Fatalf("expected empty text, got %q", text)
	}
}
