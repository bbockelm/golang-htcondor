package htcondor

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestAttrToStringRendersEveryType: group-by values arrive as whatever
// ClassAd type the attribute holds -- JobStatus is an integer, Owner a
// string -- and a group label has to be readable for all of them.
func TestAttrToStringRendersEveryType(t *testing.T) {
	ad := classad.New()
	ad.InsertAttrString("Owner", "alice")
	ad.InsertAttr("JobStatus", int64(2))
	ad.InsertAttrBool("TransferExecutable", false)

	cases := map[string]string{
		"Owner":              "alice",
		"JobStatus":          "2",
		"TransferExecutable": "false",
	}
	for attr, want := range cases {
		if got := attrToString(ad, attr); got != want {
			t.Errorf("attrToString(%s) = %q, want %q", attr, got, want)
		}
	}
}

// TestAttrToStringNamesAbsence: an attribute the job does not carry is
// a real group -- "jobs with no JobBatchName" -- and rendering it as an
// empty string makes it look like a group whose value is "". Callers
// see a blank label and read it as a bug.
func TestAttrToStringNamesAbsence(t *testing.T) {
	if got := attrToString(classad.New(), "JobBatchName"); got != "undefined" {
		t.Errorf("absent attribute rendered as %q, want %q", got, "undefined")
	}
}
