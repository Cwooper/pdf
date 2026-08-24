package pdf

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestInterpretContinuesTokensAcrossContentStreams(t *testing.T) {
	pdfData := splitTextArrayPDF()
	reader, err := NewReader(bytes.NewReader(pdfData), int64(len(pdfData)))
	if err != nil {
		t.Fatal(err)
	}

	text, err := reader.Page(1).GetPlainText(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(text); got != "Hello world" {
		t.Fatalf("text = %q, want %q", got, "Hello world")
	}
}

func splitTextArrayPDF() []byte {
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	offsets := make([]int, 7)
	writeObject := func(number int, body string) {
		offsets[number] = pdf.Len()
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", number, body)
	}
	writeStream := func(number int, content string) {
		writeObject(number, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content)+1, content))
	}

	writeObject(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObject(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	writeObject(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << /Font << /F1 6 0 R >> >> /Contents [4 0 R 5 0 R] >>")
	writeStream(4, "BT /F1 12 Tf 20 100 Td [(Hello)")
	writeStream(5, "( world)] TJ ET")
	writeObject(6, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	xrefOffset := pdf.Len()
	pdf.WriteString("xref\n0 7\n0000000000 65535 f \n")
	for number := 1; number <= 6; number++ {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offsets[number])
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xrefOffset)
	return pdf.Bytes()
}

func TestInterpretSeparatesAdjacentContentStreams(t *testing.T) {
	split := contentStreamsPDF([]string{
		"BT /F1 12 Tf 20 100 Td (Hello) Tj ET BT /F1 12 Tf 20",
		"5 Td (world) Tj ET",
	})
	whole := contentStreamsPDF([]string{
		"BT /F1 12 Tf 20 100 Td (Hello) Tj ET BT /F1 12 Tf 20 5 Td (world) Tj ET",
	})

	wantY := textY(t, whole, "world")
	gotY := textY(t, split, "world")
	if gotY != wantY {
		t.Fatalf("Y of \"world\" = %v, want %v: adjacent content streams were concatenated without a separator, gluing the operands \"20\" and \"5\" into \"205\"", gotY, wantY)
	}
}

func textY(t *testing.T, pdfData []byte, word string) float64 {
	t.Helper()
	reader, err := NewReader(bytes.NewReader(pdfData), int64(len(pdfData)))
	if err != nil {
		t.Fatal(err)
	}
	for _, txt := range reader.Page(1).Content().Text {
		if strings.Contains(word, txt.S) || strings.Contains(txt.S, word) {
			return txt.Y
		}
	}
	t.Fatalf("%q not found in page content", word)
	return 0
}

func contentStreamsPDF(streams []string) []byte {
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	numObjects := 4 + len(streams)
	offsets := make([]int, numObjects+1)
	writeObject := func(number int, body string) {
		offsets[number] = pdf.Len()
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", number, body)
	}

	contents := ""
	for i := range streams {
		if i > 0 {
			contents += " "
		}
		contents += fmt.Sprintf("%d 0 R", 4+i)
	}

	writeObject(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObject(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	writeObject(3, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << /Font << /F1 %d 0 R >> >> /Contents [%s] >>", numObjects, contents))
	for i, content := range streams {
		writeObject(4+i, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content))
	}
	writeObject(numObjects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	xrefOffset := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", numObjects+1)
	for number := 1; number <= numObjects; number++ {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offsets[number])
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", numObjects+1, xrefOffset)
	return pdf.Bytes()
}
