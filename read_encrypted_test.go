package pdf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
// /Identity, reads as plain text whatever its other entries hold, and its
// attachments fail to read rather than read as ciphertext. One naming no
// filters reads everything in the clear, attachments included.
func TestIdentityCryptFilters(t *testing.T) {
	page := pagePDF("", fmt.Sprintf("<< /Length 22 >>\nstream\nBT (Hello world) Tj ET\nendstream"),
		"<< /Type /EmbeddedFile /Length 16 >>\nstream\n0123456789abcdef\nendstream")
	for _, enc := range []string{
		"<< /Filter /Standard /V 4 /R 4 /StmF /Identity /StrF /Identity /EFF /StdCF /CF << /StdCF << /CFM /AESV2 /AuthEvent /EFOpen >> >> >>",
		"<< /Filter /Standard /V 5 /R 6 /StmF /Identity /StrF /Identity /EFF /StdCF /CF << /StdCF << /CFM /AESV3 >> >> >>",
		"<< /Filter /Standard /V 4 /R 4 >>",
	} {
		r := openPDF(t, withEncrypt(page, enc))
		if got, err := r.Page(1).GetPlainText(nil); err != nil || !strings.Contains(got, "Hello world") {
			t.Errorf("%s: GetPlainText = %q, %v; want %q", enc, got, err, "Hello world")
		}
		_, err := io.ReadAll(r.resolve(objptr{}, objptr{5, 0}).Reader())
		if wantErr := strings.Contains(enc, "/EFF"); (err != nil) != wantErr {
			t.Errorf("%s: reading the attachment: %v, want an error %v", enc, err, wantErr)
		}
	}
}

// Strings and streams can take different crypt filters, and a stream can
// name its own through a /Crypt filter (PDF 32000-1 7.4.10).
func TestMixedCryptFilters(t *testing.T) {
	for _, s := range []cryptSpec{
		{V: 4, R: 4, bits: 128, stmF: "Identity"},
		{V: 4, R: 4, bits: 128, strF: "Identity"},
		{V: 4, R: 4, bits: 128, ownCrypt: "Identity"},
		{V: 4, R: 4, bits: 128, stmF: "Identity", ownCrypt: "StdCF"},
	} {
		t.Run(fmt.Sprintf("%+v", s), func(t *testing.T) { checkDecrypts(t, s) })
	}
	data := encryptedPDF(cryptSpec{V: 4, R: 4, bits: 128, ownCrypt: "Missing"}, "BT (Hello world) Tj ET", "", "")
	if _, err := io.ReadAll(openPDF(t, data).Page(1).V.Key("Contents").Reader()); err == nil {
		t.Error("a /Crypt filter naming no crypt filter read, want an error")
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
		if got := aes256Hash(6, []byte(pw), u[32:40], nil); !bytes.Equal(got, u[:32]) {
			t.Errorf("password %q, salt %x: hash %x, want %x", pw, u[32:40], got, u[:32])
		}
	}
}

// Viewers try a password as the owner password too. An AES-256 file can have
// an empty owner password and so open with none; revisions 2 to 4 take the
// user password as the owner's when the owner's is empty (Algorithm 3).
func TestOwnerPassword(t *testing.T) {
	r, err := openFixture(t, "owner-empty-r6.pdf")
	if err != nil {
		t.Fatalf("owner-empty-r6.pdf: %v", err)
	}
	checkFixtureText(t, r, "aes two fifty six reads this")
	for _, name := range []string{"userpw-r2.pdf", "userpw-r4.pdf", "aes256-userpw.pdf"} {
		r, err := openFixture(t, name, "owner")
		if err != nil {
			t.Errorf("%s with the owner password: %v", name, err)
			continue
		}
		checkFixtureText(t, r, "aes two fifty six reads this")
	}
}

// Revisions 2 to 4 hash a password in PDFDocEncoding, and revisions 5 and 6
// after SASLprep: qpdf wrote pdfdoc-r4.pdf under "pässwörd€", whose euro sign
// Latin-1 lacks, and sasl-r6.pdf under "IX", which SASLprep makes of the
// Roman numeral nine.
func TestPasswordEncoding(t *testing.T) {
	for name, pw := range map[string]string{"pdfdoc-r4.pdf": "pässwörd€", "sasl-r6.pdf": "\u2168"} {
		r, err := openFixture(t, name, pw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkFixtureText(t, r, "aes two fifty six reads this")
	}
	// RFC 4013's examples, and a space.
	for in, want := range map[string]string{"I\u00adX": "IX", "user": "user", "USER": "USER", "\u00aa": "a", "\u2168": "IX", "a\u00a0b": "a b"} {
		if got := saslPrep(in); got != want {
			t.Errorf("saslPrep(%q) = %q, want %q", in, got, want)
		}
	}
	// NFKC proper composes the first mark and leaves the rest; norm's
	// stream-safe form would add a U+034F after the thirtieth.
	marks := "a" + strings.Repeat("\u0301", 32)
	if got, want := saslPrep(marks), "\u00e1"+strings.Repeat("\u0301", 31); got != want {
		t.Errorf("saslPrep(a and 32 acute accents) = %+q, want %+q", got, want)
	}
}

func TestSecurityHandler(t *testing.T) {
	data := withEncrypt(buildPDF("<< /Type /Catalog >>"), "<< /Filter /Adobe.PubSec /V 4 /SubFilter /adbe.pkcs7.s5 >>")
	if err := openBytes(data); !errors.Is(err, ErrSecurityHandler) {
		t.Errorf("got %v, want ErrSecurityHandler", err)
	}
}

// openWith opens data trying the passwords pw lists after the empty one.
func openWith(t *testing.T, data []byte, pw ...string) *Reader {
	t.Helper()
	r, err := NewReaderEncrypted(bytes.NewReader(data), int64(len(data)), func() string {
		if len(pw) == 0 {
			return ""
		}
		p := pw[0]
		pw = pw[1:]
		return p
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// attachment reads the embedded file encryptedPDF writes, through its file
// specification.
func attachment(r *Reader) (string, error) {
	b, err := io.ReadAll(r.resolve(objptr{}, objptr{9, 0}).Key("EF").Key("F").Reader())
	return string(b), err
}

// An attachment takes /EFF, or /StmF when there is none. In a file whose
// strings and streams are in the clear, the document opens without the
// password, its attachments open with it, and an /EFF naming no usable filter
// fails only the attachments.
func TestAttachments(t *testing.T) {
	const content = "BT (Hello world) Tj ET"
	for _, tt := range []struct {
		name string
		s    cryptSpec
		pw   []string
		want string // the attachment, or "" for an error
	}{
		{"EFF defaults to StmF", cryptSpec{V: 4, R: 4, bits: 128, attachment: "attached"}, nil, "attached"},
		{"attachments only, no password", cryptSpec{V: 4, R: 4, bits: 128, user: "secret", stmF: "Identity", strF: "Identity", eff: "StdCF", attachment: "attached"}, nil, ""},
		{"attachments only, password", cryptSpec{V: 4, R: 4, bits: 128, user: "secret", stmF: "Identity", strF: "Identity", eff: "StdCF", attachment: "attached"}, []string{"wrong", "secret"}, "attached"},
		{"no /Type", cryptSpec{V: 4, R: 4, bits: 128, user: "secret", stmF: "Identity", strF: "Identity", eff: "StdCF", attachment: "attached", attachmentNoType: true}, []string{"secret"}, "attached"},
		{"unusable EFF", cryptSpec{V: 4, R: 4, bits: 128, stmF: "Identity", strF: "Identity", eff: "Missing", attachment: "attached"}, nil, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := openWith(t, encryptedPDF(tt.s, content, "", ""), tt.pw...)
			if got, err := r.Page(1).GetPlainText(nil); err != nil || !strings.Contains(got, "Hello world") {
				t.Errorf("GetPlainText = %q, %v; want %q", got, err, "Hello world")
			}
			got, err := attachment(r)
			if tt.want == "" && err == nil || tt.want != "" && got != tt.want {
				t.Errorf("attachment = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

// Every /Encrypt entry may be an indirect reference, a stream's /Crypt filter
// with no /Name is /Identity, and a 40-bit key under revision 3 takes the
// owner password's whole MD5 through its 50 rehashes (Algorithm 3).
func TestCryptSpecVariants(t *testing.T) {
	for _, s := range []cryptSpec{
		{V: 4, R: 4, bits: 128, indirect: true},
		{V: 4, R: 4, bits: 128, ownCryptNoName: true},
	} {
		t.Run(fmt.Sprintf("%+v", s), func(t *testing.T) { checkDecrypts(t, s) })
	}
	s := cryptSpec{V: 2, R: 3, bits: 40, user: "user", owner: "owner"}
	r := openWith(t, encryptedPDF(s, "BT (Hello world) Tj ET", "", ""), "owner")
	if got, err := r.Page(1).GetPlainText(nil); err != nil || !strings.Contains(got, "Hello world") {
		t.Errorf("40-bit R3 with the owner password: GetPlainText = %q, %v", got, err)
	}
}

func TestEncryptDictErrors(t *testing.T) {
	page := streamPage("", []byte("BT (Hello world) Tj ET"))
	if got, err := plainText(t, bytes.Replace(page, []byte("/Root 1 0 R >>"), []byte("/Root 1 0 R /Encrypt 99 0 R >>"), 1)); err != nil || !strings.Contains(got, "Hello world") {
		t.Errorf("dangling /Encrypt: GetPlainText = %q, %v; want it read as unencrypted", got, err)
	}
	for _, tt := range []struct{ enc, want string }{
		{"<< /V 5 /R 6 >>", "malformed"},
		{"<< /Filter (Standard) /V 4 >>", "malformed"},
		{"<< /Filter /Standard /V 4 /R 3 /CF << /StdCF << /CFM /AESV2 >> >> /StmF /StdCF /StrF /StdCF /O <" + strings.Repeat("00", 32) + "> /U <" + strings.Repeat("00", 32) + "> >>", "malformed"},
		{"<< /Filter /Standard /V 4 /R 4 /StmF (StdCF) >>", "unsupported"},
	} {
		err := openBytes(withEncrypt(page, tt.enc))
		if err == nil || !strings.HasPrefix(err.Error(), tt.want) || errors.Is(err, ErrSecurityHandler) {
			t.Errorf("%s: got %v, want %s", tt.enc, err, tt.want)
		}
	}
	// A bad key entry in a file whose strings and streams are clear fails only
	// the attachment, with its own error.
	data := pagePDF("", "<< /Length 22 >>\nstream\nBT (Hello world) Tj ET\nendstream",
		"<< /Type /EmbeddedFile /Length 16 >>\nstream\n0123456789abcdef\nendstream")
	data = withEncrypt(data, "<< /Filter /Standard /V 5 /R 6 /StmF /Identity /StrF /Identity /EFF /StdCF /CF << /StdCF << /CFM /AESV3 >> >> /O <"+strings.Repeat("00", 48)+"> /U <"+strings.Repeat("00", 48)+"> /OE <"+strings.Repeat("00", 32)+"> /UE <00> >>")
	if _, err := io.ReadAll(openPDF(t, data).resolve(objptr{}, objptr{5, 0}).Reader()); err == nil || !strings.HasPrefix(err.Error(), "malformed") {
		t.Errorf("attachment with a short /UE: %v, want the malformed-key error", err)
	}
}
