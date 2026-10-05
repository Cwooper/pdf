package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"
)

// streamPage returns a one-page file whose content stream holds data under
// the stream dictionary entries dict.
func streamPage(dict string, data []byte) []byte {
	return buildPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d %s >>\nstream\n%s\nendstream", len(data), dict, data),
	)
}

func deflate(data []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

func plainText(t *testing.T, data []byte) (string, error) {
	t.Helper()
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return r.Page(1).GetPlainText(nil)
}

// TestPredictorDefaultColumns verifies that a predictor with no /Columns
// decodes rows of one byte, the spec's default: rows of none consumed the
// whole inflate and yielded nothing.
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
