package main

import (
"reflect"
"testing"
)

func TestTransformScopes(t *testing.T) {
tests := []struct {
name     string
input    []string
expected []string
}{
{
name:     "bare HTCondor scopes",
input:    []string{"READ", "WRITE"},
expected: []string{"condor:/READ", "condor:/WRITE"},
},
{
name:     "already prefixed scopes",
input:    []string{"condor:/READ", "condor:/WRITE"},
expected: []string{"condor:/READ", "condor:/WRITE"},
},
{
name:     "mixed scopes",
input:    []string{"READ", "openid", "mcp:read", "condor:/WRITE"},
expected: []string{"condor:/READ", "openid", "mcp:read", "condor:/WRITE"},
},
{
name:     "empty and whitespace",
input:    []string{"READ", "", "  ", "WRITE"},
expected: []string{"condor:/READ", "condor:/WRITE"},
},
{
name:     "scopes with slashes",
input:    []string{"READ", "path/to/resource"},
expected: []string{"condor:/READ", "path/to/resource"},
},
}

for _, tt := range tests {
t.Run(tt.name, func(t *testing.T) {
result := transformScopes(tt.input)
if !reflect.DeepEqual(result, tt.expected) {
t.Errorf("transformScopes(%v) = %v, want %v", tt.input, result, tt.expected)
}
})
}
}
