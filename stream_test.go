package pdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"strings"
	"testing"
)

func TestValueReaderOnNonStream(t *testing.T) {
	v := testValue(int64(1))
	rd := v.Reader()
	data, err := io.ReadAll(rd)
	if err == nil {
		t.Fatal("expected error reading non-stream value")
	}
	if !strings.Contains(err.Error(), "stream not present") {
		t.Fatalf("error = %q, want it to mention 'stream not present'", err)
	}
	if len(data) != 0 {
		t.Fatalf("read %q, want empty", data)
	}
}

func TestPNGUpReader(t *testing.T) {
	// Two rows of width 2 encoded with the PNG "Up" predictor (filter byte 2).
	// Row 1: raw [5, 10]; Row 2: raw [1, 1] (differences from the previous row).
	input := []byte{2, 5, 10, 2, 1, 1}
	r := &pngUpReader{r: bytes.NewReader(input), hist: make([]byte, 3), tmp: make([]byte, 3)}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	// hist accumulates: after row1 [5,10]; after row2 [5+1, 10+1] = [6,11].
	want := []byte{5, 10, 6, 11}
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded = %v, want %v", got, want)
	}
}

func TestPNGUpReaderRejectsBadFilter(t *testing.T) {
	input := []byte{1, 5, 10} // filter byte 1 is not "Up"
	r := &pngUpReader{r: bytes.NewReader(input), hist: make([]byte, 3), tmp: make([]byte, 3)}
	_, err := io.ReadAll(r)
	if err == nil || !strings.Contains(err.Error(), "malformed PNG-Up") {
		t.Fatalf("err = %v, want malformed PNG-Up error", err)
	}
}

func TestCBCReader(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{0x05}, 16)
	plaintext := []byte("abcdefghijklmnopabcdefghijklmnop") // 32 bytes (2 blocks)
	ct := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plaintext)

	r := &cbcReader{
		cbc: cipher.NewCBCDecrypter(block, iv),
		rd:  bytes.NewReader(ct),
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestCryptKeyDeterministicAndSaltAware(t *testing.T) {
	k1 := cryptKey([]byte("secret"), cryptRC4, objptr{id: 1, gen: 0})
	k2 := cryptKey([]byte("secret"), cryptRC4, objptr{id: 1, gen: 0})
	if !bytes.Equal(k1, k2) {
		t.Fatal("cryptKey is not deterministic")
	}
	if k3 := cryptKey([]byte("secret"), cryptAESV2, objptr{id: 1, gen: 0}); bytes.Equal(k1, k3) {
		t.Fatal("cryptKey should differ when AES adds its salt")
	}
	if k4 := cryptKey([]byte("secret"), cryptRC4, objptr{id: 2, gen: 0}); bytes.Equal(k1, k4) {
		t.Fatal("cryptKey should differ when object id differs")
	}
	// PDF 32000-1:2008 Algorithm 1 step e: the object key is the first
	// min(n/8+5, 16) bytes of the digest, so 11 for this 6-byte key and 16
	// only once the document key is 11 bytes or longer.
	if len(k1) != 11 {
		t.Fatalf("object key length for a 6-byte key = %d, want 11", len(k1))
	}
	if k5 := cryptKey([]byte("0123456789abcdef"), cryptRC4, objptr{id: 1, gen: 0}); len(k5) != 16 {
		t.Fatalf("object key length for a 16-byte key = %d, want 16", len(k5))
	}
}

func TestDecryptStringRC4RoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	ptr := objptr{id: 3, gen: 1}
	plaintext := "hello, encrypted world"

	// RC4 is a stream cipher; applying the same keystream twice recovers the
	// plaintext, so decrypt is its own inverse here.
	enc := new(stringDecrypter).decrypt(key, cryptRC4, ptr, plaintext)
	if enc == plaintext {
		t.Fatal("RC4 pass did not transform the plaintext")
	}
	if got := new(stringDecrypter).decrypt(key, cryptRC4, ptr, enc); got != plaintext {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}
}

func TestDecryptStringAESRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	ptr := objptr{id: 7, gen: 2}

	derived := cryptKey(key, cryptAESV2, ptr)
	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{0x01}, 16)
	plaintext := []byte("0123456789abcdef") // exactly one block, no padding
	ct := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plaintext)

	sealed := string(append(append([]byte{}, iv...), ct...))
	if got := new(stringDecrypter).decrypt(key, cryptAESV2, ptr, sealed); got != string(plaintext) {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}
}

func TestCryptFilterMethod(t *testing.T) {
	for _, tt := range []struct {
		param dict
		V     int64
		want  cryptMethod
		ok    bool
	}{
		{dict{"CFM": name("AESV2"), "Length": int64(16), "AuthEvent": name("DocOpen")}, 4, cryptAESV2, true},
		{dict{"CFM": name("AESV2"), "Length": int64(128)}, 4, cryptAESV2, true},
		{dict{"CFM": name("V2")}, 4, cryptRC4, true},
		{dict{"CFM": name("AESV2"), "AuthEvent": name("EFOpen")}, 4, cryptAESV2, true},
		{dict{"CFM": name("AESV3"), "Length": int64(32)}, 5, cryptAESV3, true},
		{dict{"CFM": name("AESV3"), "Length": int64(256)}, 5, cryptAESV3, true},
		{dict{"CFM": name("AESV2"), "Length": int64(8)}, 4, 0, false},
		{dict{"CFM": name("AESV3"), "Length": int64(16)}, 5, 0, false},
		{dict{"CFM": name("AESV2"), "AuthEvent": name("Other")}, 4, 0, false},
		{dict{"CFM": name("None")}, 4, 0, false},
		{dict{"CFM": name("AESV3")}, 4, 0, false},
		{dict{"CFM": name("AESV2")}, 5, 0, false},
		{nil, 4, 0, false},
	} {
		if got, ok := cryptFilterMethod(tt.param, tt.V); got != tt.want || ok != tt.ok {
			t.Errorf("V%d %v: got %v, %v; want %v, %v", tt.V, tt.param, got, ok, tt.want, tt.ok)
		}
	}

	// A string or stream filter no method serves is unsupported.
	for _, enc := range []string{
		"<< /Filter /Standard /V 4 /R 4 /CF << /StdCF << /CFM /None >> >> /StmF /StdCF /StrF /StdCF >>",
		"<< /Filter /Standard /V 4 /R 4 /CF << /StdCF << /CFM /AESV3 >> >> /StmF /StdCF /StrF /StdCF >>",
		"<< /Filter /Standard /V 5 /R 6 /CF << /StdCF << /CFM /V2 >> >> /StmF /StdCF /StrF /StdCF >>",
		"<< /Filter /Standard /V 4 /R 4 /StmF /StdCF /StrF /StdCF >>",
		"<< /Filter /Standard /V 4 /R 4 /CF << /StdCF << /CFM /AESV2 >> >> /StmF /StdCF /StrF /Other >>",
	} {
		if err := openBytes(withEncrypt(buildPDF("<< /Type /Catalog >>"), enc)); err == nil || !strings.HasPrefix(err.Error(), "unsupported") {
			t.Errorf("%s: got %v, want unsupported", enc, err)
		}
	}
}
