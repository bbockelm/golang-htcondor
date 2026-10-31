//go:build libcondor_utils

package fuzzsubmit

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// TestToolDaemonBufferNoopJavaMatchOracle pins four families attribute by
// attribute: the tool daemon (TDP), the buffer settings, the noop job and the
// java settings.
//
// The sweep alone would not be enough. It compares whatever the generator
// happens to write, and these families are easy to write in a way that never
// reaches an ad: everything but tool_daemon_cmd is ignored unless
// tool_daemon_cmd is there, and the argument keywords land in one of two
// attributes depending on how the value was quoted, so a sweep can be green
// about a spelling it never produced. Each case here names the attributes the
// oracle must produce, so a family that stopped reaching the comparison fails
// instead of passing quietly.
func TestToolDaemonBufferNoopJavaMatchOracle(t *testing.T) {
	requireOracle(t)

	cases := []struct {
		name   string
		src    string
		want   map[string]string // attribute -> the value the oracle must have
		absent []string          // attributes neither side may set
	}{{
		name: "tdp_full",
		src: "executable = /bin/sleep\ntool_daemon_cmd = /usr/bin/strace\n" +
			"tool_daemon_args = -f -p 1\ntool_daemon_input = in.txt\n" +
			"tool_daemon_output = out.txt\ntool_daemon_error = err.txt\n" +
			"suspend_job_at_exec = true\nqueue\n",
		want: map[string]string{
			"ToolDaemonCmd":    `"/usr/bin/strace"`,
			"ToolDaemonArgs":   `"-f -p 1"`,
			"ToolDaemonInput":  `"in.txt"`,
			"ToolDaemonOutput": `"out.txt"`,
			"ToolDaemonError":  `"err.txt"`,
			"SuspendJobAtExec": "true",
		},
		absent: []string{"ToolDaemonArguments"},
	}, {
		// A relative tool-daemon path is NOT resolved against Iwd:
		// check_and_universalize_path only rewrites mapped drive letters,
		// and only on Windows.
		name:   "tdp_relative_path_is_not_resolved",
		src:    "executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\nqueue\n",
		want:   map[string]string{"ToolDaemonCmd": `"tdp.sh"`},
		absent: []string{"ToolDaemonArgs", "ToolDaemonArguments"},
	}, {
		// The V1 spelling collapses runs of whitespace between arguments
		// and cannot carry an argument containing one.
		name: "tdp_args_v1_whitespace",
		src:  "executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_args = -a    -b\t-c\nqueue\n",
		want: map[string]string{"ToolDaemonArgs": `"-a -b -c"`},
	}, {
		name: "tdp_args_v1_escaped_quote",
		src:  "executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_args = -m \\\"a b\\\"\nqueue\n",
		want: map[string]string{"ToolDaemonArgs": `"-m \"a b\""`},
	}, {
		// The V2 spelling keeps an argument with a space in it, under the
		// other attribute name.
		name: "tdp_arguments_v2",
		src:  "executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_arguments = \"-f 'a b' c\"\nqueue\n",
		// join_args quotes the offending CHARACTER, not the argument, so
		// the space in `a b` comes back as a' 'b.
		want:   map[string]string{"ToolDaemonArguments": `"-f a' 'b c"`},
		absent: []string{"ToolDaemonArgs"},
	}, {
		name:   "tdp_arguments2",
		src:    "executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_arguments2 = \"-f 'a b'\"\nqueue\n",
		want:   map[string]string{"ToolDaemonArguments": `"-f a' 'b"`},
		absent: []string{"ToolDaemonArgs"},
	}, {
		// Without the daemon itself nothing in the family is read.
		name: "tdp_without_cmd_sets_nothing",
		src: "executable = /bin/sleep\ntool_daemon_args = -f\ntool_daemon_input = in.txt\n" +
			"tool_daemon_output = out.txt\nsuspend_job_at_exec = true\nqueue\n",
		absent: []string{"ToolDaemonCmd", "ToolDaemonArgs", "ToolDaemonArguments",
			"ToolDaemonInput", "ToolDaemonOutput", "SuspendJobAtExec"},
	}, {
		// Each keyword's attribute name is a submit keyword in its own right.
		name: "tdp_attribute_spellings",
		src:  "executable = /bin/sleep\nToolDaemonCmd = tdp.sh\nToolDaemonArgs = -f\nToolDaemonOutput = out.txt\nqueue\n",
		want: map[string]string{
			"ToolDaemonCmd":    `"tdp.sh"`,
			"ToolDaemonArgs":   `"-f"`,
			"ToolDaemonOutput": `"out.txt"`,
		},
	}, {
		// All three buffer settings are expressions, so arithmetic survives.
		name: "buffer_settings",
		src: "executable = /bin/sleep\nbuffer_files = \"a.txt = b.txt\"\n" +
			"buffer_size = 1024\nbuffer_block_size = 2 * 1024\nqueue\n",
		want: map[string]string{
			"BufferFiles":     `"a.txt = b.txt"`,
			"BufferSize":      "1024",
			"BufferBlockSize": "2 * 1024",
		},
	}, {
		name: "noop_job",
		src:  "executable = /bin/sleep\nnoop_job = true\nnoop_job_exit_code = 42\nnoop_job_exit_signal = 9\nqueue\n",
		want: map[string]string{
			"IsNoopJob":         "true",
			"NoopJobExitCode":   "42",
			"NoopJobExitSignal": "9",
		},
	}, {
		name: "noop_job_expression",
		src:  "executable = /bin/sleep\nnoop_job = (JobStatus == 1)\nqueue\n",
		want: map[string]string{"IsNoopJob": "(JobStatus == 1)"},
	}, {
		// Neither jar_files nor the java VM arguments are gated on the java
		// universe.
		name: "java_keywords_outside_the_java_universe",
		src:  "executable = /bin/sleep\njar_files = a.jar, b.jar\njava_vm_arguments = -Xmx128m -server\nqueue\n",
		want: map[string]string{
			"JarFiles":   `"a.jar, b.jar"`,
			"JavaVMArgs": `"-Xmx128m -server"`,
		},
		absent: []string{"JavaVMArguments"},
	}, {
		name:   "java_vm_args_v2",
		src:    "executable = /bin/sleep\njava_vm_args = \"-Xmx128m -Dx='a b'\"\nqueue\n",
		want:   map[string]string{"JavaVMArguments": `"-Xmx128m -Dx=a' 'b"`},
		absent: []string{"JavaVMArgs"},
	}, {
		name: "java_universe",
		src: "universe = java\nexecutable = Main\njar_files = app.jar\narguments = MyClass\n" +
			"java_vm_arguments2 = \"-server -Dx='a b'\"\nqueue\n",
		want: map[string]string{
			"JarFiles":        `"app.jar"`,
			"JavaVMArguments": `"-server -Dx=a' 'b"`,
		},
		absent: []string{"JavaVMArgs"},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cpp := oracle.MakeAds(tc.src, oracle.ModeAds, MaxProcs)
			if !cpp.OK {
				t.Fatalf("oracle rejected the file: %s", cpp.Err)
			}
			cppAds, err := ParseCanon(cpp.Ads)
			if err != nil {
				t.Fatalf("malformed oracle output: %v", err)
			}
			goRes := GoMakeAds(tc.src)
			if !goRes.OK {
				t.Fatalf("Go parser rejected the file: %s", goRes.Err)
			}

			for _, key := range cppAds.Keys() {
				goAttrs, ok := goRes.Ads.ByKey[key]
				if !ok {
					t.Fatalf("Go produced no ad %s", key)
				}
				for attr, want := range tc.want {
					cppVal, has := lookupFold(cppAds.ByKey[key], attr)
					if !has {
						t.Fatalf("%s %s: the oracle does not set it, so this case no longer reaches the family", key, attr)
					}
					if !sameValue(cppVal, want) {
						t.Errorf("%s %s: oracle has %s, this test expected %s", key, attr, cppVal, want)
					}
					goVal, goHas := lookupFold(goAttrs, attr)
					if !goHas {
						t.Errorf("%s %s: only C++ has it (=%s)", key, attr, cppVal)
					} else if !sameValue(cppVal, goVal) {
						t.Errorf("%s %s: cpp=%s go=%s", key, attr, cppVal, goVal)
					}
				}
				for _, attr := range tc.absent {
					if v, has := lookupFold(cppAds.ByKey[key], attr); has {
						t.Errorf("%s %s: the oracle sets it (=%s); this test's premise is wrong", key, attr, v)
					}
					if v, has := lookupFold(goAttrs, attr); has {
						t.Errorf("%s %s: only Go has it (=%s)", key, attr, v)
					}
				}
			}
		})
	}
}

// TestToolDaemonRejectsWhatCondorSubmitRejects pins the errors, which are the
// other half of parity: a file condor_submit refuses must not quietly produce
// a job here.
func TestToolDaemonRejectsWhatCondorSubmitRejects(t *testing.T) {
	requireOracle(t)

	for _, src := range []string{
		// Both spellings of one setting.
		"executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_args = -f\ntool_daemon_arguments = -g\nqueue\n",
		"executable = /bin/sleep\njava_vm_args = -a\njava_vm_arguments = -b\nqueue\n",
		// V1 and V2 together without allow_arguments_v1.
		"executable = /bin/sleep\ntool_daemon_cmd = tdp.sh\ntool_daemon_args = -f\ntool_daemon_arguments2 = \"-g\"\nqueue\n",
		"executable = /bin/sleep\njava_vm_arguments = -a\njava_vm_arguments2 = \"-b\"\nqueue\n",
	} {
		t.Run(strings.ReplaceAll(firstLine(src), " ", "_"), func(t *testing.T) {
			if oracle.MakeAds(src, oracle.ModeAds, MaxProcs).OK {
				t.Fatalf("the oracle accepted this file, so it is the wrong example:\n%s", src)
			}
			if goRes := GoMakeAds(src); goRes.OK {
				t.Errorf("the Go parser accepted a file condor_submit rejects:\n%s", src)
			}
		})
	}
}

// TestGeneratedCorpusReachesTheseFamilies is the other half of deleting these
// entries from knownDivergentGenerated. Once an attribute agrees it leaves
// that table, and nothing else would notice if the generator stopped writing
// the keyword that produces it: the sweep would be green about a family it
// never exercised. This asserts the fixed sweep still puts each attribute in
// front of the oracle.
func TestGeneratedCorpusReachesTheseFamilies(t *testing.T) {
	requireOracle(t)
	v := genVocab(t)

	want := []string{
		"ToolDaemonCmd", "ToolDaemonArgs", "ToolDaemonArguments",
		"ToolDaemonInput", "ToolDaemonOutput", "ToolDaemonError",
		"SuspendJobAtExec",
		"BufferFiles", "BufferSize", "BufferBlockSize",
		"IsNoopJob", "NoopJobExitCode", "NoopJobExitSignal",
		"JarFiles", "JavaVMArgs", "JavaVMArguments",
	}

	seen := map[string]bool{}
	for _, data := range generatedCorpus(600) {
		cpp := oracle.MakeAds(v.Generate(data), oracle.ModeAds, MaxProcs)
		if !cpp.OK {
			continue
		}
		ads, err := ParseCanon(cpp.Ads)
		if err != nil {
			continue
		}
		for _, key := range ads.Keys() {
			for _, attr := range want {
				if _, has := lookupFold(ads.ByKey[key], attr); has {
					seen[attr] = true
				}
			}
		}
	}
	for _, attr := range want {
		if !seen[attr] {
			t.Errorf("no generated file makes the oracle set %s: the sweep no longer reaches it", attr)
		}
	}
}
