package htcondor

import (
	"fmt"
	"slices"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// javaCmd is what a java job's Cmd becomes: the literal string "java", not a
// path. The starter resolves it against the execute machine's JAVA
// configuration, which is the whole point -- the JVM is the execute node's,
// not the submit node's.
const javaCmd = "java"

// applyJavaUniverse rewrites a java job the way SetTransferFiles does, once
// the transfer settings are known.
//
// A java job's `executable` is not a program: it is the entry CLASS, and the
// class name to run is in `arguments`. condor_submit turns that into a job
// the starter can run by putting the class on the transfer list, replacing
// Cmd with "java", and turning TransferExecutable off -- the last one because
// the file transfer renames executables, and a renamed class file is not the
// class the JVM was asked for.
//
// Without the rewrite the ad says to EXECUTE the class file. A java job
// submitted through this library would have had the execute node try to run
// Hello.class as a program, and not find it there either, since nothing put
// it in the sandbox.
//
// None of it happens for a job that transfers nothing (should_transfer_files
// = NO): the class is expected to be on the execute machine already, Cmd
// stays the path it was given, and TransferExecutable is left alone.
func (sf *SubmitFile) applyJavaUniverse(ad *classad.ClassAd, inFileList *[]string, should shouldTransferFiles) {
	if sf.universe != UniverseJava || should == stfNo {
		return
	}

	// The entry class, as the path the executable resolved to. C++ reads it
	// back out of the ad for exactly this reason -- it wants the resolved
	// path, not the submit file's text -- and skips it when Cmd is already
	// the JVM.
	if cmd, ok := ad.EvaluateAttrString("Cmd"); ok && cmd != javaCmd {
		if !slices.Contains(*inFileList, cmd) {
			*inFileList = append(*inFileList, cmd)
		}
	}

	// jar_files is split on COMMAS, so `jar_files = a.jar b.jar` is one
	// entry naming a file with a space in it -- HTCondor's reading, not a
	// typo here. Each entry goes on the transfer list whether or not it is
	// already there.
	//
	// Read from the keyword rather than the ad: the Go parser writes the
	// JarFiles attribute after the transfer settings, where condor_submit
	// writes it before, and setBufferNoopAndJarFiles stores it verbatim so
	// the keyword is the same value.
	if jars := sf.submitParam("jar_files", "JarFiles"); jars != "" {
		for _, jar := range strings.Split(jars, ",") {
			if jar = strings.TrimSpace(jar); jar != "" {
				*inFileList = append(*inFileList, jar)
			}
		}
	}

	_ = ad.Set("Cmd", javaCmd)
	_ = ad.Set("TransferExecutable", false)
}

// requireJavaClass is SetArguments' java check: a java job has to name the
// class to run, and condor_submit refuses the submit file when it does not.
//
// It is read off the ad rather than from the keyword because that is where
// the answer is after the arguments have been parsed -- either spelling, V1
// or V2, and either one empty means no class was named.
func (sf *SubmitFile) requireJavaClass(ad *classad.ClassAd) error {
	if sf.universe != UniverseJava {
		return nil
	}
	for _, attr := range []string{"Args", "Arguments"} {
		if v, ok := ad.EvaluateAttrString(attr); ok && strings.TrimSpace(v) != "" {
			return nil
		}
	}
	return fmt.Errorf("in the java universe you must specify the class name to run, " +
		"for example: arguments = MyClass")
}
