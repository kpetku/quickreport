package quickreport

import (
	"strings"
	"testing"
)

var example = `site1.com clean clean
site2.com blacklisted clean 
site3.com blacklisted malwarefound 
site4.com clean malwarefound
site5.com clean malwarefound 
site6.com clean clean
site7.com clean clean
site8.com clean clean
site9.com clean malwarefound 
site9.com clean clean
sitea.com blacklisted malwarefound`

func TestCanReadListTxtClobbering(t *testing.T) {
	Clobber = true
	result, err := New("testData/list.txt", Clobber)
	if err != nil {
		t.Logf("missing list.txt in testData folder")
		t.Fail()
	}
	if result.Blacklisted != 3 || result.NoIssuesFound != 4 || result.MalwareDetected != 5 {
		t.Fail()
	}
}
func TestCanReadListTxtNotClobbering(t *testing.T) {
	Clobber = false
	result, err := New("testData/list.txt", Clobber)
	if err != nil {
		t.Logf("missing list.txt in testData folder")
		t.Fail()
	}
	if result.Blacklisted != 3 || result.NoIssuesFound != 5 || result.MalwareDetected != 5 {
		t.Fail()
	}
}
func TestOpeningInvalidFile(t *testing.T) {
	_, err := New("testData/there-is-no-file.txt", Clobber)
	if err == nil {
		t.Fail()
	}
}
func TestOpeningLongLineFile(t *testing.T) {
	var empty Result
	result, err := New("testData/longline.txt", Clobber)
	if err != nil {
		t.Fail()
	}
	if result != empty {
		t.Fail()
	}
}
func TestMalformedBlacklistField(t *testing.T) {
	r := new(Result)
	example := `site1.com sdafkghl clean`
	_, err := r.parse(strings.NewReader(example))
	if err == nil {
		t.Fail()
	}
}
func TestMalformedMalwareFoundField(t *testing.T) {
	r := new(Result)
	example := `site1.com clean sdafkghl`
	_, err := r.parse(strings.NewReader(example))
	if err == nil {
		t.Fail()
	}
}
func TestMalformedLongLine(t *testing.T) {
	r := new(Result)
	example := `site1.com clean clean
	site2.com clean clean
	site3.com blacklisted malwarefound trailing`
	_, err := r.parse(strings.NewReader(example))
	if err == nil {
		t.Fail()
	}
}
func BenchmarkParse(b *testing.B) {
	r := new(Result)
	for n := 0; n < b.N; n++ {
		r.parse(strings.NewReader(example))
	}
}
