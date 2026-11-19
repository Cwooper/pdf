package pdf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// openFixture opens testdata/name, trying the passwords pw lists after the
// empty one.
func openFixture(t *testing.T, name string, pw ...string) (*Reader, error) {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	next := func() string {
		if len(pw) == 0 {
			return ""
		}
		p := pw[0]
		pw = pw[1:]
		return p
	}
	var r *Reader
	mustNotCrash(t, func() { r, err = NewReaderEncrypted(strings.NewReader(string(data)), int64(len(data)), next) })
	return r, err
}

func checkFixtureText(t *testing.T, r *Reader, line string) {
	t.Helper()
	text, err := r.Page(1).GetPlainText(nil)
	if err != nil {
		t.Fatalf("page text: %v", err)
	}
	if !strings.Contains(text, line) {
		t.Fatalf("page text %q does not carry %q", text, line)
	}
}

// A one-line page encrypted by pdfcpu with 40-bit RC4 (/V 1 /R 2) and an empty
// user password. PDF 32000-1 Algorithm 1 truncates the per-object key to
// min(n/8+5, 16) bytes: 10 here, where the whole digest is only right for a
// 128-bit key.
func TestReads40BitRC4WithEmptyUserPassword(t *testing.T) {
	r, err := openFixture(t, "rc4-40.pdf")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	checkFixtureText(t, r, "forty bit rc4 reads this line")
}

// One-line pages encrypted by qpdf with AES-256 and an empty user password,
// as an editing restriction leaves a file: revision 6 (PDF 2.0's hash rounds)
// and the deprecated revision 5 (one SHA-256). Strings decrypt too.
func TestReadsAES256WithEmptyUserPassword(t *testing.T) {
	for _, name := range []string{"aes256-r6.pdf", "aes256-r5.pdf"} {
		t.Run(name, func(t *testing.T) {
			r, err := openFixture(t, name)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			checkFixtureText(t, r, "aes two fifty six reads this")
			if got := r.Trailer().Key("Info").Key("Title").Text(); got != "Restricted" {
				t.Errorf("Info title = %q, want %q", got, "Restricted")
			}
		})
	}
}

func TestAES256UserPassword(t *testing.T) {
	if _, err := openFixture(t, "aes256-userpw.pdf"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("no password: err = %v, want ErrInvalidPassword", err)
	}
	if _, err := openFixture(t, "aes256-userpw.pdf", "wrong"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("wrong password: err = %v, want ErrInvalidPassword", err)
	}
	r, err := openFixture(t, "aes256-userpw.pdf", "wrong", "user")
	if err != nil {
		t.Fatalf("user password: %v", err)
	}
	checkFixtureText(t, r, "aes two fifty six reads this")
}

// An AES-256 dictionary with short entries or an impossible revision is
// malformed, and one with a later revision or another crypt filter is
// unsupported.
func TestAES256EncryptDict(t *testing.T) {
	hex := func(n int) string { return "<" + strings.Repeat("00", n) + ">" }
	entries := func(o, u, oe, ue int) string {
		return " /O " + hex(o) + " /U " + hex(u) + " /OE " + hex(oe) + " /UE " + hex(ue)
	}
	cf := func(cfm, length string) string {
		return " /CF << /StdCF << /CFM /" + cfm + " /Length " + length + " >> >> /StmF /StdCF /StrF /StdCF"
	}
	full := entries(48, 48, 32, 32)
	for _, tt := range []struct {
		name, dict, want string
	}{
		{"short U", cf("AESV3", "32") + " /R 6" + entries(48, 47, 32, 32), "malformed"},
		{"short O", cf("AESV3", "32") + " /R 6" + entries(40, 48, 32, 32), "malformed"},
		{"short UE", cf("AESV3", "32") + " /R 6" + entries(48, 48, 32, 16), "malformed"},
		{"missing OE", cf("AESV3", "32") + " /R 6 /O " + hex(48) + " /U " + hex(48) + " /UE " + hex(32), "malformed"},
		{"revision 4", cf("AESV3", "32") + " /R 4" + full, "malformed"},
		{"revision 7", cf("AESV3", "32") + " /R 7" + full, "unsupported"},
		{"AESV2 filter", cf("AESV2", "16") + " /R 6" + full, "unsupported"},
		{"128-bit filter", cf("AESV3", "16") + " /R 6" + full, "unsupported"},
		// All-zero entries hash to nothing the empty password matches.
		{"well formed", cf("AESV3", "256") + " /R 6" + full, ErrInvalidPassword.Error()},
		{"longer entries", cf("AESV3", "32") + " /R 5" + entries(127, 127, 48, 48), ErrInvalidPassword.Error()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := withEncrypt(buildPDF("<< /Type /Catalog >>"), "<< /Filter /Standard /V 5"+tt.dict+" >>")
			if err := openBytes(data); err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("got %v, want %q", err, tt.want)
			}
		})
	}
}

// A file that encrypts only its attachments, its strings and streams under
// /Identity, reads as plain text whatever its other entries hold; one with
// only streams under /Identity is unsupported.
func TestIdentityCryptFilters(t *testing.T) {
	page := streamPage("", []byte("BT (Hello world) Tj ET"))
	for _, enc := range []string{
		"<< /Filter /Standard /V 4 /R 4 /StmF /Identity /StrF /Identity /EFF /StdCF /CF << /StdCF << /CFM /AESV2 >> >> >>",
		"<< /Filter /Standard /V 5 /R 6 /StmF /Identity /StrF /Identity /EFF /StdCF /CF << /StdCF << /CFM /AESV3 >> >> >>",
	} {
		if got, err := plainText(t, withEncrypt(page, enc)); err != nil || !strings.Contains(got, "Hello world") {
			t.Errorf("%s: GetPlainText = %q, %v; want %q", enc, got, err, "Hello world")
		}
	}
	mixed := "<< /Filter /Standard /V 5 /R 6 /StmF /Identity /StrF /StdCF /CF << /StdCF << /CFM /AESV3 >> >> >>"
	if err := openBytes(withEncrypt(page, mixed)); err == nil || !strings.HasPrefix(err.Error(), "unsupported") {
		t.Errorf("mixed filters: got %v, want unsupported", err)
	}
}

func TestHeaderVersion(t *testing.T) {
	r, err := openFixture(t, "pdf20.pdf")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	checkFixtureText(t, r, "aes two fifty six reads this")
	for header, want := range map[string]bool{
		"%PDF-1.0\n": true, "%PDF-1.7\r": true, "%PDF-2.0\n": true, "%PDF-2.1\r": true,
		"%PDF-1.8\n": false, "%PDF-3.0\n": false, "%PDF-2.0 ": false, "%PDF-20\n\n": false, "%PDF-2.": false,
	} {
		if got := validHeader([]byte(header)); got != want {
			t.Errorf("validHeader(%q) = %v, want %v", header, got, want)
		}
	}
}

// testdata/aes256-r6-hashes.tsv holds user passwords and the /U entries qpdf
// wrote for them, each with fresh salts, so that the hash's rounds end at many
// different counts.
func TestAES256HashMatchesQpdf(t *testing.T) {
	data, err := os.ReadFile("testdata/aes256-r6-hashes.tsv")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(data)) {
		pw, uhex, _ := strings.Cut(strings.TrimSuffix(line, "\n"), "\t")
		u, err := hex.DecodeString(uhex)
		if err != nil || len(u) != aes256OULen {
			t.Fatalf("bad vector %q", line)
		}
		if got := aes256Hash(6, []byte(pw), u[32:40]); !bytes.Equal(got, u[:32]) {
			t.Errorf("password %q, salt %x: hash %x, want %x", pw, u[32:40], got, u[:32])
		}
	}
}
