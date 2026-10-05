package pdf

import (
	"fmt"
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
