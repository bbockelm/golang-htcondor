package htcondor

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/PelicanPlatform/classad/classad"
)

// A URL in transfer_input_files is fetched by the execute node, not
// uploaded from here. It must not reach the spool allow-set, because
// SpoolJobFilesFromFS stats every name in that set and fails the whole
// job on the first one that is not a real path -- which took out every
// surface built on the FS spool path for a perfectly legal submit file.
func TestURLsAreNotSpoolInputs(t *testing.T) {
	tests := []struct {
		name          string
		transferInput string
		wantFiles     []string
		wantURLs      []string
	}{
		{
			name:          "https URL alongside a real file",
			transferInput: "local.txt,https://example.com/ref.fa",
			wantFiles:     []string{"local.txt"},
			wantURLs:      []string{"https://example.com/ref.fa"},
		},
		{
			// The schemes a site actually uses for large reference
			// data. None of them name a file this access point holds.
			name:          "the usual schemes",
			transferInput: "s3://b/o,osdf:///ns/f,pelican://fed/f,davs://h/f,file:///etc/hosts,gs://b/o",
			wantFiles:     nil,
			wantURLs: []string{
				"s3://b/o", "osdf:///ns/f", "pelican://fed/f",
				"davs://h/f", "file:///etc/hosts", "gs://b/o",
			},
		},
		{
			// A name is not a URL just because it contains a colon or
			// a slash. Over-stripping would silently drop a real input.
			name:          "paths that merely look url-ish",
			transferInput: "a:b.txt,dir/sub/file.dat,./rel.txt,weird::name.txt",
			wantFiles:     []string{"./rel.txt", "a:b.txt", "dir/sub/file.dat", "weird::name.txt"},
			wantURLs:      nil,
		},
		{
			name:          "no URLs at all",
			transferInput: "one.txt,two.txt",
			wantFiles:     []string{"one.txt", "two.txt"},
			wantURLs:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad := classad.New()
			if err := ad.Set("TransferInput", tt.transferInput); err != nil {
				t.Fatalf("set TransferInput: %v", err)
			}
			if err := ad.Set("TransferExecutable", false); err != nil {
				t.Fatalf("set TransferExecutable: %v", err)
			}

			files, urls := inputFilesAndURLs(ad)
			if got := keysSorted(files); !equalStringSlices(got, tt.wantFiles) {
				t.Errorf("files = %v, want %v", got, tt.wantFiles)
			}
			if len(urls) != len(tt.wantURLs) {
				t.Errorf("urls = %v, want %v", urls, tt.wantURLs)
			}
		})
	}
}

// The failure this fixes, end to end through the thing that broke:
// every name in the allow-set is handed to fs.Stat, and a URL is not a
// valid fs path, so one URL used to fail the whole job.
func TestAllowSetIsStattableWithURLsPresent(t *testing.T) {
	ad := classad.New()
	if err := ad.Set("TransferInput", "local.txt,https://example.com/ref.fa"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := ad.Set("TransferExecutable", false); err != nil {
		t.Fatalf("set: %v", err)
	}

	fsys := fstest.MapFS{"local.txt": {Data: []byte("hello")}}
	for name := range getInputFilesFromJobAd(ad) {
		if _, err := fs.Stat(fsys, name); err != nil {
			t.Fatalf("allow-set entry %q cannot be stat'd (%v); "+
				"SpoolJobFilesFromFS returns this as an error and fails the job", name, err)
		}
	}
}

// SpoolInputAllowSet is what a caller is told it may upload. Listing a
// URL there is worse than useless: it invites an upload under a name
// the schedd will never match.
func TestSpoolInputAllowSetOmitsURLs(t *testing.T) {
	ad := classad.New()
	if err := ad.Set("TransferInput", "local.txt,https://example.com/ref.fa"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := ad.Set("TransferExecutable", false); err != nil {
		t.Fatalf("set: %v", err)
	}

	got := SpoolInputAllowSet(ad)
	if !equalStringSlices(got, []string{"local.txt"}) {
		t.Errorf("SpoolInputAllowSet = %v, want just local.txt", got)
	}
}

// The executable still joins the set when there are URLs around it:
// stripping must not take the one thing a minimal job spools.
func TestExecutableSurvivesAlongsideURLs(t *testing.T) {
	ad := classad.New()
	if err := ad.Set("TransferInput", "https://example.com/ref.fa"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := ad.Set("Cmd", "/home/alice/run.sh"); err != nil {
		t.Fatalf("set: %v", err)
	}

	got := keysSorted(getInputFilesFromJobAd(ad))
	if !equalStringSlices(got, []string{"run.sh"}) {
		t.Errorf("got %v, want just run.sh", got)
	}
}
