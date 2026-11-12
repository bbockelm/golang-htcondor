package httpserver

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// specDoc parses the served OpenAPI document.
func specDoc(t *testing.T) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(openAPISchema), &doc); err != nil {
		t.Fatalf("the OpenAPI document is not valid JSON: %v", err)
	}
	return doc
}

// A site app is told to check /openapi.json rather than guess at
// endpoints. That rule is only honest if the endpoints a site app
// actually needs are in there -- /auth/me was not, so the first thing
// an app author had to do was break the rule.
func TestAuthMeIsDocumented(t *testing.T) {
	doc := specDoc(t)
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatal("no paths object")
	}
	if _, ok := paths["/auth/me"]; !ok {
		t.Fatal("/auth/me is not in the OpenAPI document; a site app cannot discover how to identify its user")
	}
	if _, ok := paths["/site/"]; ok {
		t.Error("/site/ is served as HTML, not API, and should not be in the API document")
	}
}

// The documented response and the Go struct must not drift. A spec
// that says `user` while the server sends `username` is worse than no
// spec: it is wrong with authority.
func TestAuthMeSchemaMatchesTheStruct(t *testing.T) {
	doc := specDoc(t)
	components, _ := doc["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	schema, ok := schemas["AuthMeResponse"].(map[string]any)
	if !ok {
		t.Fatal("no AuthMeResponse schema")
	}
	props, _ := schema["properties"].(map[string]any)

	// Every documented property must exist on the struct, by its JSON
	// name. The reverse is not required: a field may be deliberately
	// undocumented, but a documented field that does not exist is a
	// lie a caller will act on.
	jsonNames := map[string]bool{}
	rt := reflect.TypeOf(AuthMeResponse{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		jsonNames[strings.Split(tag, ",")[0]] = true
	}
	for name := range props {
		if !jsonNames[name] {
			t.Errorf("the spec documents AuthMeResponse.%s, which the Go struct does not send", name)
		}
	}

	// The fields a site app is actually told to rely on.
	for _, required := range []string{"authenticated", "username", "groups", "site_apps", "app_only"} {
		if _, ok := props[required]; !ok {
			t.Errorf("AuthMeResponse schema omits %q", required)
		}
	}
}

func TestSiteAppSchemaMatchesTheStruct(t *testing.T) {
	doc := specDoc(t)
	components, _ := doc["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	schema, ok := schemas["SiteApp"].(map[string]any)
	if !ok {
		t.Fatal("no SiteApp schema")
	}
	props, _ := schema["properties"].(map[string]any)

	jsonNames := map[string]bool{}
	rt := reflect.TypeOf(SiteAppSummary{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		jsonNames[strings.Split(tag, ",")[0]] = true
	}
	for name := range props {
		if !jsonNames[name] {
			t.Errorf("the spec documents SiteApp.%s, which SiteAppSummary does not send", name)
		}
	}
	for _, required := range []string{"id", "name", "url", "home"} {
		if _, ok := props[required]; !ok {
			t.Errorf("SiteApp schema omits %q", required)
		}
	}
}
