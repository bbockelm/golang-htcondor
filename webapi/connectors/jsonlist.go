package connectors

import "encoding/json"

// parseJSONList reads the JSON-array form of a list, and reports whether
// the value was one.
//
// False means "not a JSON array of strings" -- either it does not begin
// with "[", or it does not parse -- and the caller then applies the
// comma rule to it. The same split site apps makes, so a list written
// one way in one setting and the other way in another behaves the same.
func parseJSONList(raw string) ([]string, bool) {
	if len(raw) == 0 || raw[0] != '[' {
		return nil, false
	}
	var items []string
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, s := range items {
		if s != "" {
			out = append(out, s)
		}
	}
	return out, true
}
