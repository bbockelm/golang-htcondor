package htcondor

import (
	"strings"
	"testing"
)

const remoteIOSubmit = "executable = /bin/true\n" +
	"buffer_size = 1024\nbuffer_files = \"a = b\"\nbuffer_block_size = 2048\n" +
	"file_remaps = \"c = d\"\nfetch_files = f.txt\ncompress_files = g.txt\n" +
	"append_files = h.txt\nlocal_files = i.txt\nqueue\n"

// TestOmitRemoteIOKeywords pins both shapes. The keywords stay ACCEPTED on
// both sides of the gate -- an unrecognized submit command is an ordinary
// macro, not an error, which is what condor_submit does with them once they
// are gone -- so what the gate changes is only whether they write attributes.
func TestOmitRemoteIOKeywords(t *testing.T) {
	attrs := []string{
		"BufferSize", "BufferFiles", "BufferBlockSize", "FileRemaps",
		"FetchFiles", "CompressFiles", "AppendFiles", "LocalFiles",
	}

	def := keywordAttrs(t, remoteIOSubmit, SubmitBehavior{})
	for _, a := range attrs {
		if !def[strings.ToLower(a)] {
			t.Errorf("%s is absent by default, so the gate guards nothing", a)
		}
	}

	on := keywordAttrs(t, remoteIOSubmit, SubmitBehavior{OmitRemoteIOKeywords: true})
	for _, a := range attrs {
		if on[strings.ToLower(a)] {
			t.Errorf("%s is still written with OmitRemoteIOKeywords set", a)
		}
	}
	// Accepting the file is the point: a removed keyword must not become a
	// parse error for a submit file that still carries it.
	if len(on) == 0 {
		t.Fatal("the submit file produced no ad at all")
	}
	if !on["cmd"] {
		t.Error("the rest of the job ad should be unaffected")
	}
}

// TestOmitContainerIsCommonAttr pins the one keyword HTCondor kept while
// taking its attribute away.
func TestOmitContainerIsCommonAttr(t *testing.T) {
	src := "executable = /bin/true\ncontainer_is_common = true\nqueue\n"

	if !keywordAttrs(t, src, SubmitBehavior{})["containeriscommon"] {
		t.Error("ContainerIsCommon is absent by default, so the gate guards nothing")
	}
	if keywordAttrs(t, src, SubmitBehavior{OmitContainerIsCommonAttr: true})["containeriscommon"] {
		t.Error("ContainerIsCommon is still written with the gate set")
	}
}

// TestRemoteIOKeywordsAreNotAltNames is the invariant that lets these rows be
// dropped at all. kwAltName means "skip this row if the one before it
// matched", so the table's ORDER is load-bearing: removing a row that is
// either half of such a pair would change how the other is read.
func TestRemoteIOKeywordsAreNotAltNames(t *testing.T) {
	all := SimpleSubmitKeywords()
	for i, kw := range all {
		if !remoteIOKeywords[kw.Key] {
			continue
		}
		if kw.Opts&kwAltName != 0 {
			t.Errorf("%s is an alternate spelling, so dropping it changes how the row before it reads", kw.Key)
		}
		if i+1 < len(all) && all[i+1].Opts&kwAltName != 0 {
			t.Errorf("%s is followed by the alternate spelling %s, which would lose its antecedent",
				kw.Key, all[i+1].Key)
		}
	}
}

// TestSimpleSubmitKeywordsForDropsOnlyWhatItNames guards the filter itself.
func TestSimpleSubmitKeywordsForDropsOnlyWhatItNames(t *testing.T) {
	full := SimpleSubmitKeywords()
	filtered := SimpleSubmitKeywordsFor(SubmitBehavior{
		OmitRemoteIOKeywords: true, OmitContainerIsCommonAttr: true,
	})
	if len(filtered) != len(full)-len(remoteIOKeywords)-1 {
		t.Errorf("filtered table has %d rows, want %d", len(filtered), len(full)-len(remoteIOKeywords)-1)
	}
	kept := map[string]bool{}
	for _, kw := range filtered {
		kept[kw.Key] = true
	}
	for _, kw := range full {
		gone := remoteIOKeywords[kw.Key] || kw.Key == "container_is_common"
		if gone == kept[kw.Key] {
			t.Errorf("%s: dropped=%v, want dropped=%v", kw.Key, !kept[kw.Key], gone)
		}
	}
	// The order the table is walked in is part of its meaning.
	j := 0
	for _, kw := range full {
		if j < len(filtered) && filtered[j].Key == kw.Key {
			j++
		}
	}
	if j != len(filtered) {
		t.Error("the filtered table is not in the order of the full one")
	}
}

// keywordAttrs parses src under one behavior and returns which attributes the
// job ad carries, lower-cased.
func keywordAttrs(t *testing.T, src string, b SubmitBehavior) map[string]bool {
	t.Helper()
	sf, err := ParseSubmitFileWithOptions(strings.NewReader(src), SubmitParseOptions{Behavior: b})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	out := map[string]bool{}
	for _, n := range ad.GetAttributes() {
		out[strings.ToLower(n)] = true
	}
	return out
}
