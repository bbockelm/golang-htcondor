package fuzzconfig

import (
	"sort"
	"strings"
)

// Canon normalizes a "KEY\x1Fvalue\n" table so the two engines can be compared
// without spurious differences in key casing or ordering. HTCondor config keys
// are case-insensitive, so keys are uppercased; values are left untouched
// (they are literal). Records are re-sorted by the normalized key. If two
// records collapse to the same key after uppercasing (which should not happen —
// each engine already dedups by key), the last one wins, matching config
// last-assignment semantics.
func Canon(table string) string {
	if table == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(table, "\n"), "\n")
	byKey := make(map[string]string, len(lines))
	keys := make([]string, 0, len(lines))
	for _, line := range lines {
		sep := strings.IndexByte(line, 0x1f)
		if sep < 0 {
			// No separator: treat the whole line as a key with an empty value so
			// a malformed record still surfaces rather than being dropped.
			key := strings.ToUpper(line)
			if _, seen := byKey[key]; !seen {
				keys = append(keys, key)
			}
			byKey[key] = ""
			continue
		}
		key := strings.ToUpper(line[:sep])
		if _, seen := byKey[key]; !seen {
			keys = append(keys, key)
		}
		byKey[key] = line[sep+1:]
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0x1f)
		b.WriteString(byKey[k])
		b.WriteByte('\n')
	}
	return b.String()
}
