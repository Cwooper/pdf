package pdf

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestOpenMissingFile guards against the regression where os.Open failing
// used to call f.Close() on a nil *os.File, turning a simple "file not
// found" into a nil-pointer panic.
func TestOpenMissingFile(t *testing.T) {
	f, r, err := Open("testdata/does-not-exist.pdf")
	if err == nil {
		t.Fatal("expected error opening missing file, got nil")
	}
	if f != nil {
		t.Fatal("expected nil *os.File on open failure")
	}
	if r != nil {
		t.Fatal("expected nil *Reader on open failure")
	}
}

func TestNewReaderRejectsInvalidHeader(t *testing.T) {
	data := []byte("this is not a pdf at all")
	_, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "invalid header") {
		t.Fatalf("err = %v, want 'invalid header' error", err)
	}
}

// TestLenientFileEnd verifies that a file opens with bytes after its %%EOF,
// or with none at all, so long as its last startxref lies in the last 1,024
// bytes.
func TestLenientFileEnd(t *testing.T) {
	const window = 1024
	for _, name := range []string{"pdf20.pdf", "ascii85_flate_chain.pdf", "rc4-40.pdf"} {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		want := fileText(t, data)
		tail := data[bytes.LastIndex(data, []byte("startxref")):]
		tests := []struct {
			name string
			data []byte
			ok   bool
		}{
			{"junk after %%EOF", slices.Concat(data, []byte("<signature>\r\n trailing junk")), true},
			{"nulls after %%EOF", slices.Concat(data, make([]byte, 512)), true},
			{"no %%EOF", bytes.TrimSuffix(bytes.TrimRight(data, "\r\n"), []byte("%%EOF")), true},
			{"no line after startxref", bytes.TrimRight(bytes.TrimSuffix(bytes.TrimRight(data, "\r\n"), []byte("%%EOF")), "\r\n"), true},
			{"startxref first in the window", slices.Concat(data, make([]byte, window-len(tail))), true},
			{"startxref before the window", slices.Concat(data, make([]byte, window-len(tail)+1)), false},
		}
		for _, tt := range tests {
			t.Run(name+" "+tt.name, func(t *testing.T) {
				_, err := NewReader(bytes.NewReader(tt.data), int64(len(tt.data)))
				if !tt.ok {
					if err == nil || !strings.Contains(err.Error(), "startxref") {
						t.Errorf("err = %v, want missing startxref", err)
					}
					return
				}
				if got := fileText(t, tt.data); got != want {
					t.Errorf("text = %q, want %q", got, want)
				}
			})
		}
	}
}

// TestLenientFileStart verifies that a file opens with bytes before its
// header, so long as the header starts in the first 1,024 bytes, reading its
// offsets from the header.
func TestLenientFileStart(t *testing.T) {
	const window = 1024
	for _, name := range []string{"pdf20.pdf", "ascii85_flate_chain.pdf", "rc4-40.pdf"} {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		want := fileText(t, data)
		tests := []struct {
			name string
			junk []byte
			ok   bool
		}{
			{"a mail header", []byte("Content-Type: application/pdf\r\n\r\n"), true},
			{"a stray %PDF- before the header", []byte("%PDF-junk\n"), true},
			{"the header at the window's end", make([]byte, window), true},
			{"the header past the window", make([]byte, window+1), false},
		}
		for _, tt := range tests {
			t.Run(name+" "+tt.name, func(t *testing.T) {
				data := slices.Concat(tt.junk, data)
				_, err := NewReader(bytes.NewReader(data), int64(len(data)))
				if !tt.ok {
					if err == nil || !strings.Contains(err.Error(), "invalid header") {
						t.Errorf("err = %v, want invalid header", err)
					}
					return
				}
				if got := fileText(t, data); got != want {
					t.Errorf("text = %q, want %q", got, want)
				}
			})
		}
	}
}

// fileText returns the text of every page of data.
func fileText(t *testing.T, data []byte) string {
	t.Helper()
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	rd, err := r.GetPlainText()
	if err != nil {
		t.Fatal(err)
	}
	text, _ := io.ReadAll(rd)
	return string(text)
}

func TestNewReaderRejectsMissingStartXref(t *testing.T) {
	data := []byte("%PDF-1.4\n" + strings.Repeat("x", 200) + "\n%%EOF\n")
	_, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "startxref") {
		t.Fatalf("err = %v, want missing startxref error", err)
	}
}

// encryptedPDFWithBadPassword builds a minimal single-object PDF whose trailer
// carries a Standard-security /Encrypt dictionary (V=1, R=2, 40-bit) with O and
// U values that do not match the empty password. NewReaderEncrypted must then
// consult the password callback, which returns "" to stop immediately.
func encryptedPDFWithBadPassword() []byte {
	// O and U must each be 32 bytes; ID can be any string.
	o := strings.Repeat("O", 32)
	u := strings.Repeat("U", 32)
	id := strings.Repeat("I", 16)

	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	xrefOffset := pdf.Len()
	pdf.WriteString("xref\n0 1\n0000000000 65535 f \n")
	fmt.Fprintf(&pdf, "trailer\n<< /Size 1 /ID [(%s)] /Encrypt << /Filter /Standard /V 1 /R 2 /Length 40 /O (%s) /U (%s) /P 0 >> >>\n", id, o, u)
	fmt.Fprintf(&pdf, "startxref\n%d\n%%%%EOF\n", xrefOffset)
	return pdf.Bytes()
}

func TestNewReaderEncryptedStopsOnEmptyPassword(t *testing.T) {
	var calls int
	pw := func() string {
		calls++
		return ""
	}

	data := encryptedPDFWithBadPassword()
	_, err := NewReaderEncrypted(bytes.NewReader(data), int64(len(data)), pw)
	if err != ErrInvalidPassword {
		t.Fatalf("err = %v, want ErrInvalidPassword", err)
	}
	if calls != 1 {
		t.Fatalf("pw called %d times, want 1 (empty string should stop immediately)", calls)
	}
}

func TestEnsureXrefLen(t *testing.T) {
	var table []xref
	table = ensureXrefLen(table, 3, 8)
	if len(table) != 4 || cap(table) < 4 {
		t.Fatalf("len/cap = %d/%d, want len 4", len(table), cap(table))
	}
	table[3] = xref{ptr: objptr{id: 3}}
	// Already-large-enough table is returned unchanged.
	table2 := ensureXrefLen(table, 1, 8)
	if len(table2) != len(table) || table2[3].ptr.id != 3 {
		t.Fatal("ensureXrefLen mutated an already-sufficient table")
	}
	// Doubling would pass the limit, so growth stops at it.
	table3 := ensureXrefLen(make([]xref, 4), 4, 6)
	if len(table3) != 5 || cap(table3) != 6 {
		t.Fatalf("len/cap = %d/%d, want 5/6", len(table3), cap(table3))
	}
}
