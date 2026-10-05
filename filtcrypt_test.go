package pdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
)

// streamPage returns a one-page file whose content stream holds data under
// the stream dictionary entries dict.
func streamPage(dict string, data []byte) []byte {
	return pagePDF("", fmt.Sprintf("<< /Length %d %s >>\nstream\n%s\nendstream", len(data), dict, data))
}

func plainText(t *testing.T, data []byte) (string, error) {
	t.Helper()
	return openPDF(t, data).Page(1).GetPlainText(nil)
}

// TestPredictorDefaultColumns verifies that a predictor with no /Columns
// decodes rows of one byte, the spec's default.
func TestPredictorDefaultColumns(t *testing.T) {
	var rows []byte
	var prev byte
	for _, c := range []byte("BT (Hi) Tj ET") {
		rows = append(rows, 2, c-prev)
		prev = c
	}
	z := deflate(rows)
	got, err := plainText(t, streamPage("/Filter /FlateDecode /DecodeParms << /Predictor 12 >>", z))
	if err != nil || !strings.Contains(got, "Hi") {
		t.Errorf("no /Columns: GetPlainText = %q, %v; want %q", got, err, "Hi")
	}
	if _, err := plainText(t, streamPage("/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 0 >>", z)); err == nil || !strings.Contains(err.Error(), "Columns") {
		t.Errorf("/Columns 0: got %v, want it reported", err)
	}
}

// TestFlateIgnoresAdler32 verifies that complete deflate data reads although
// the Adler-32 trailer after it is wrong or missing, as other readers allow.
func TestFlateIgnoresAdler32(t *testing.T) {
	z := deflate([]byte("BT (Hello) Tj ET"))
	bad := bytes.Clone(z)
	bad[len(bad)-1] ^= 0xff
	for name, data := range map[string][]byte{"bad": bad, "missing": z[:len(z)-4], "short": z[:len(z)-2]} {
		got, err := plainText(t, streamPage("/Filter /FlateDecode", data))
		if err != nil || !strings.Contains(got, "Hello") {
			t.Errorf("%s trailer: GetPlainText = %q, %v; want %q", name, got, err, "Hello")
		}
	}
	if _, err := plainText(t, streamPage("/Filter /FlateDecode", z[:len(z)-6])); err == nil {
		t.Error("truncated deflate data: got no error")
	}
}

// withEncrypt returns data, a file from buildPDF, with encrypt as its
// trailer's /Encrypt entry.
func withEncrypt(data []byte, encrypt string) []byte {
	return bytes.Replace(data, []byte("/Root 1 0 R >>"), []byte("/Root 1 0 R /Encrypt "+encrypt+" /ID [<"+hex.EncodeToString([]byte(testID))+"> <>] >>"), 1)
}

const testID = "0123456789abcdef"

// TestAES256Unsupported verifies that AES-256 files are reported as
// unsupported rather than malformed.
func TestAES256Unsupported(t *testing.T) {
	data := withEncrypt(buildPDF("<< /Type /Catalog >>"), "<< /Filter /Standard /V 5 /R 6 /Length 256 /CF << /StdCF << /CFM /AESV3 /Length 32 >> >> /StmF /StdCF /StrF /StdCF >>")
	if err := openBytes(data); err == nil || !strings.HasPrefix(err.Error(), "unsupported") {
		t.Errorf("got %v, want AES-256 reported as unsupported", err)
	}
}

// A cryptSpec describes the Standard security handler encryptedPDF writes,
// for the empty user password. Its derivations are written out from the
// spec rather than shared with the reader, so that a mistake there shows.
type cryptSpec struct {
	V, R, bits int    // AESV2 when V is 4, else RC4
	cfLength   string // the crypt filter's /Length, if any
	noMetadata bool   // /EncryptMetadata false, with a metadata stream
}

// fileKey derives the file key (Algorithm 2).
func (s cryptSpec) fileKey(O string) []byte {
	h := md5.New()
	h.Write(passwordPad)
	h.Write([]byte(O))
	h.Write([]byte{0xfc, 0xff, 0xff, 0xff}) // /P -4
	h.Write([]byte(testID))
	if s.noMetadata {
		h.Write([]byte{0xff, 0xff, 0xff, 0xff})
	}
	key := h.Sum(nil)
	n := s.bits / 8
	if s.R >= 3 {
		for range 50 {
			sum := md5.Sum(key[:n])
			key = sum[:]
		}
	}
	return key[:n]
}

// userEntry computes /U (Algorithms 4 and 5).
func (s cryptSpec) userEntry(key []byte) []byte {
	if s.R == 2 {
		u := bytes.Clone(passwordPad)
		c, _ := rc4.NewCipher(key)
		c.XORKeyStream(u, u)
		return u
	}
	sum := md5.Sum(append(bytes.Clone(passwordPad), testID...))
	u := sum[:]
	for i := range 20 {
		k := bytes.Clone(key)
		for j := range k {
			k[j] ^= byte(i)
		}
		c, _ := rc4.NewCipher(k)
		c.XORKeyStream(u, u)
	}
	return append(u, make([]byte, 16)...)
}

// encrypt encrypts data as object id's (Algorithm 1).
func (s cryptSpec) encrypt(key []byte, id int, data []byte) []byte {
	h := md5.New()
	h.Write(key)
	h.Write([]byte{byte(id), byte(id >> 8), byte(id >> 16), 0, 0})
	if s.V == 4 {
		h.Write([]byte("sAlT"))
	}
	k := h.Sum(nil)[:min(len(key)+5, 16)]
	if s.V != 4 {
		out := make([]byte, len(data))
		c, _ := rc4.NewCipher(k)
		c.XORKeyStream(out, data)
		return out
	}
	pad := 16 - len(data)%16
	data = append(bytes.Clone(data), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := append(bytes.Repeat([]byte{7}, 16), make([]byte, len(data))...)
	b, _ := aes.NewCipher(k)
	cipher.NewCBCEncrypter(b, out[:16]).CryptBlocks(out[16:], data)
	return out
}

// encryptedPDF returns a file encrypted under s whose page shows content and
// whose one outline item is titled title. Page object 3 carries pageExtra as
// it stands.
func encryptedPDF(s cryptSpec, content, title, pageExtra string) []byte {
	O := strings.Repeat("O", 32)
	key := s.fileKey(O)
	strm := s.encrypt(key, 4, []byte(content))
	enc := fmt.Sprintf("<< /Filter /Standard /V %d /R %d /Length %d /O <%x> /U <%x> /P -4", s.V, s.R, s.bits, O, s.userEntry(key))
	if s.V == 4 {
		cfLength := ""
		if s.cfLength != "" {
			cfLength = " /Length " + s.cfLength
		}
		enc += fmt.Sprintf(" /CF << /StdCF << /CFM /AESV2%s >> >> /StmF /StdCF /StrF /StdCF", cfLength)
	}
	catalog := "<< /Type /Catalog /Pages 2 0 R /Outlines 5 0 R >>"
	if s.noMetadata {
		enc += " /EncryptMetadata false"
		catalog = "<< /Type /Catalog /Pages 2 0 R /Outlines 5 0 R /Metadata 8 0 R >>"
	}
	objs := []string{
		catalog,
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /Contents 4 0 R " + pageExtra + " >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(strm), strm),
		"<< /Type /Outlines /First 6 0 R /Last 6 0 R /Count 1 >>",
		fmt.Sprintf("<< /Title <%x> /Parent 5 0 R >>", s.encrypt(key, 6, []byte(title))),
		enc + " >>",
	}
	if s.noMetadata {
		objs = append(objs, "<< /Type /Metadata /Subtype /XML /Length 12 >>\nstream\n<x:xmpmeta/>\nendstream")
	}
	return withEncrypt(buildPDF(objs...), "7 0 R")
}

// TestAESStringPadding verifies that an AES-encrypted string loses its
// PKCS#7 padding, a whole block of it when the text fills its last block.
func TestAESStringPadding(t *testing.T) {
	s := cryptSpec{V: 4, R: 4, bits: 128}
	for _, title := range []string{"Chapter One", "Sixteen bytes!!!", ""} {
		data := encryptedPDF(s, "", title, "")
		r := openPDF(t, data)
		if o := r.Outline(); len(o.Child) != 1 || o.Child[0].Title != title {
			t.Errorf("Outline = %q, want one item titled %q", o.Child, title)
		}
	}
}

// checkDecrypts verifies that the file encryptedPDF builds from s reads
// back its page text and outline title.
func checkDecrypts(t *testing.T, s cryptSpec) {
	t.Helper()
	data := encryptedPDF(s, "BT (Hello world) Tj ET", "Chapter One", "")
	r := openPDF(t, data)
	if got, err := r.Page(1).GetPlainText(nil); err != nil || !strings.Contains(got, "Hello world") {
		t.Errorf("GetPlainText = %q, %v; want %q", got, err, "Hello world")
	}
	if o := r.Outline(); len(o.Child) != 1 || o.Child[0].Title != "Chapter One" {
		t.Errorf("Outline = %+v, want one item titled %q", o, "Chapter One")
	}
}

// TestCryptFilterLengthBits verifies that a crypt filter's /Length is
// accepted in bits as well as in bytes.
func TestCryptFilterLengthBits(t *testing.T) {
	for _, l := range []string{"16", "128"} {
		t.Run(l, func(t *testing.T) {
			checkDecrypts(t, cryptSpec{V: 4, R: 4, bits: 128, cfLength: l})
		})
	}
}

// TestEncryptMetadataFalse verifies that a file leaving its metadata in the
// clear derives its key accordingly (Algorithm 2, step f) and that its
// metadata stream reads as it stands.
func TestEncryptMetadataFalse(t *testing.T) {
	s := cryptSpec{V: 4, R: 4, bits: 128, noMetadata: true}
	checkDecrypts(t, s)
	data := encryptedPDF(s, "", "", "")
	r := openPDF(t, data)
	if got, err := io.ReadAll(r.Trailer().Key("Root").Key("Metadata").Reader()); string(got) != "<x:xmpmeta/>" {
		t.Errorf("metadata = %q, %v; want it in the clear", got, err)
	}
}
