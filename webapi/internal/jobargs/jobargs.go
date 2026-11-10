// Package jobargs splits a job ad's argument list back into argv.
//
// A job ad carries its arguments in one of two syntaxes: Arguments, the
// "new" (V2) syntax, or Args, the "old" (V1) one. Which one depends on
// how the job was submitted, so a reader has to handle both.
package jobargs

import (
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// SplitV2 splits an Arguments value written in the V2 syntax:
// arguments are separated by whitespace outside single quotes,
// whitespace inside them is literal, and a doubled single quote inside
// a quoted run is one literal quote. A pair of quotes with nothing
// between them is an empty argument.
//
// The double quotes around the value in a submit file belong to the
// submit file, not to the job ad, so the value here starts straight
// into the arguments.
func SplitV2(s string) []string {
	var (
		out    []string
		cur    strings.Builder
		inQ    bool
		inWord bool
	)
	flush := func() {
		if inWord {
			out = append(out, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && inQ && i+1 < len(s) && s[i+1] == '\'':
			cur.WriteByte('\'')
			i++
		case c == '\'':
			inQ = !inQ
			inWord = true
		case !inQ && isSpace(c):
			flush()
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return out
}

// SplitV1 splits an Args value written in the V1 syntax, which has no
// quoting: whitespace separates arguments.
func SplitV1(s string) []string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return nil
	}
	return f
}

// FromAd returns a job's argv: Arguments when the ad has a non-empty
// one, else Args.
func FromAd(ad *classad.ClassAd) []string {
	if raw, ok := ad.EvaluateAttrString("Arguments"); ok && strings.TrimSpace(raw) != "" {
		return SplitV2(raw)
	}
	if raw, ok := ad.EvaluateAttrString("Args"); ok {
		return SplitV1(raw)
	}
	return nil
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
