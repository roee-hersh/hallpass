package itest

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func req(method, rawurl, ct string) *http.Request {
	u, _ := url.Parse(rawurl)
	r := &http.Request{Method: method, URL: u, Header: http.Header{}}
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	return r
}

const oas3 = `{
 "openapi": "3.0.0",
 "servers": [{"url": "https://api.example.com/v4"}],
 "components": {"parameters": {"per": {"name": "per_page", "in": "query", "schema": {"type": "integer"}}},
   "schemas": {"Review": {"type": "object", "required": ["spec"], "properties": {"spec": {"type": "object"}}}}},
 "paths": {
  "/repos/{owner}/{repo}/collaborators/{username}/permission": {"get": {"parameters": [{"$ref": "#/components/parameters/per"}]}},
  "/repos/{owner}/{repo}": {"get": {}, "delete": {}},
  "/users": {"get": {"parameters": [{"name": "search", "in": "query", "required": true}]}},
  "/reviews": {"post": {"requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Review"}}}}}}
 }}`

func TestOpenAPI3(t *testing.T) {
	s, err := LoadSpec("t", []byte(oas3))
	if err != nil {
		t.Fatal(err)
	}
	ok := []*http.Request{
		req("GET", "https://x/repos/acme/api/collaborators/dana/permission?per_page=1", ""),
		req("GET", "https://x/v4/repos/acme/api", ""),
		req("DELETE", "https://x/repos/acme/a.b", ""),
		req("GET", "https://x/users?search=a", ""),
	}
	for _, r := range ok {
		if err := s.Validate(r, nil); err != nil {
			t.Errorf("%s %s: %v", r.Method, r.URL, err)
		}
	}
	bad := map[string]*http.Request{
		"unknown path":     req("GET", "https://x/repos/acme", ""),
		"wrong method":     req("POST", "https://x/repos/acme/api", ""),
		"missing required": req("GET", "https://x/users", ""),
		"undeclared query": req("GET", "https://x/repos/acme/api?foo=1", ""),
		"empty segment":    req("GET", "https://x/repos//api", ""),
	}
	for name, r := range bad {
		if err := s.Validate(r, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := s.Validate(req("POST", "https://x/reviews", "application/json"), []byte(`{"spec":{}}`)); err != nil {
		t.Error(err)
	}
	if err := s.Validate(req("POST", "https://x/reviews", "application/json"), []byte(`{"kind":"x"}`)); err == nil || !strings.Contains(err.Error(), "spec") {
		t.Errorf("missing required body property accepted: %v", err)
	}
	if err := s.Validate(req("POST", "https://x/reviews", "application/json"), nil); err == nil {
		t.Error("missing required body accepted")
	}
	if err := s.Validate(req("POST", "https://x/reviews", "text/plain"), []byte("x")); err == nil {
		t.Error("wrong content type accepted")
	}
}

const oas2 = `{"swagger": "2.0", "basePath": "/api", "paths": {
 "/users.lookupByEmail": {"get": {"parameters": [{"name": "email", "in": "query", "required": true}, {"name": "token", "in": "query"}]}},
 "/permissions/check": {"post": {"parameters": [{"name": "body", "in": "body", "required": true, "schema": {"required": ["accountId"]}}]}}
}}`

func TestSwagger2(t *testing.T) {
	s, err := LoadSpec("t", []byte(oas2))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(req("GET", "https://x/api/users.lookupByEmail?email=a", ""), nil); err != nil {
		t.Error(err)
	}
	if err := s.Validate(req("GET", "https://x/users.lookupByEmail", ""), nil); err == nil {
		t.Error("missing email accepted")
	}
	if err := s.Validate(req("POST", "https://x/permissions/check", "application/json"), []byte(`{"accountId":"1"}`)); err != nil {
		t.Error(err)
	}
	if err := s.Validate(req("POST", "https://x/permissions/check", "application/json"), []byte(`{}`)); err == nil {
		t.Error("missing accountId accepted")
	}
}

const yamlSpec = `
openapi: 3.0.1
paths:
  /projects/{id}/members/all/{user_id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
`

func TestYAMLSpec(t *testing.T) {
	s, err := LoadSpec("t", []byte(yamlSpec))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(req("GET", "https://x/projects/acme%2Fapi/members/all/7", ""), nil); err != nil {
		t.Error(err)
	}
}

const disc = `{"discoveryVersion": "v1", "servicePath": "drive/v3/", "parameters": {"fields": {"location": "query"}},
 "resources": {"files": {"methods": {"get": {"path": "files/{fileId}", "httpMethod": "GET",
   "parameters": {"fileId": {"location": "path", "required": true}, "supportsAllDrives": {"location": "query"}}}}},
  "users": {"resources": {"settings": {"methods": {"list": {"path": "admin/directory/v1/users", "httpMethod": "GET", "parameters": {"customer": {"location": "query", "required": true}}}}}}}}}`

func TestDiscovery(t *testing.T) {
	s, err := LoadSpec("t", []byte(disc))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(req("GET", "https://x/drive/v3/files/abc?supportsAllDrives=true&fields=capabilities", ""), nil); err != nil {
		t.Error(err)
	}
	if err := s.Validate(req("GET", "https://x/drive/v3/files/abc?nope=1", ""), nil); err == nil {
		t.Error("undeclared query accepted")
	}
	if err := s.Validate(req("GET", "https://x/drive/v3/admin/directory/v1/users", ""), nil); err == nil {
		t.Error("missing customer accepted")
	}
	if err := s.Validate(req("POST", "https://x/drive/v3/files/abc", ""), nil); err == nil {
		t.Error("wrong method accepted")
	}
}

const boto = `{"metadata": {"protocol": "query"}, "operations": {"AssumeRole": {"input": {"shape": "AssumeRoleRequest"}}},
 "shapes": {"AssumeRoleRequest": {"type": "structure", "required": ["RoleArn", "RoleSessionName"], "members": {"RoleArn": {}, "RoleSessionName": {}, "ExternalId": {}, "PolicyArns": {}}}}}`

const botoJSON = `{"metadata": {"protocol": "json", "targetPrefix": "AWSIdentityStore"}, "operations": {"GetUserId": {"input": {"shape": "In"}}},
 "shapes": {"In": {"type": "structure", "required": ["IdentityStoreId", "AlternateIdentifier"], "members": {"IdentityStoreId": {}, "AlternateIdentifier": {}}}}}`

func TestBotocore(t *testing.T) {
	s, err := LoadSpec("t", []byte(boto))
	if err != nil {
		t.Fatal(err)
	}
	post := req("POST", "https://sts/", "application/x-www-form-urlencoded")
	if err := s.Validate(post, []byte("Action=AssumeRole&Version=2011-06-15&RoleArn=a&RoleSessionName=s&PolicyArns.member.1=x")); err != nil {
		t.Error(err)
	}
	if err := s.Validate(post, []byte("Action=AssumeRole&RoleArn=a")); err == nil {
		t.Error("missing member accepted")
	}
	if err := s.Validate(post, []byte("Action=Nope")); err == nil {
		t.Error("unknown action accepted")
	}
	if err := s.Validate(post, []byte("Action=AssumeRole&RoleArn=a&RoleSessionName=s&Bogus=1")); err == nil {
		t.Error("unknown parameter accepted")
	}
	j, err := LoadSpec("t", []byte(botoJSON))
	if err != nil {
		t.Fatal(err)
	}
	r := req("POST", "https://is/", "application/x-amz-json-1.1")
	r.Header.Set("X-Amz-Target", "AWSIdentityStore.GetUserId")
	if err := j.Validate(r, []byte(`{"IdentityStoreId":"d","AlternateIdentifier":{}}`)); err != nil {
		t.Error(err)
	}
	if err := j.Validate(r, []byte(`{"IdentityStoreId":"d"}`)); err == nil {
		t.Error("missing member accepted")
	}
	r.Header.Set("X-Amz-Target", "Other.GetUserId")
	if err := j.Validate(r, []byte(`{}`)); err == nil {
		t.Error("wrong target prefix accepted")
	}
}

func TestServerUseSpec(t *testing.T) {
	spec, _ := LoadSpec("t", []byte(oas3))
	srv := NewServer(t)
	srv.UseSpec(spec, SpecOptions{StripPrefix: []string{`/ex/[a-z]+/[a-f0-9-]+`}, IgnorePaths: []string{`^/token$`}, AllowQuery: []string{"team_id"}})
	srv.JSON("GET", "/ex/jira/abc-1/repos/acme/api", 200, `{}`)
	srv.JSON("POST", "/token", 200, `{}`)
	c := srv.Client()
	// Valid through a stripped prefix and an allowed extra query parameter.
	if _, err := c.Get(srv.URL + "/ex/jira/abc-1/repos/acme/api?team_id=T1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Post(srv.URL+"/token", "application/x-www-form-urlencoded", nil); err != nil {
		t.Fatal(err)
	}
	if srv.Calls() == nil {
		t.Fatal("no calls")
	}
	if srv.spec == nil {
		t.Fatal("spec not set")
	}
}

func TestOptionalParams(t *testing.T) {
	s, _ := LoadSpec("t", []byte(oas2))
	r := req("GET", "https://x/api/users.lookupByEmail", "")
	if err := s.Validate(r, nil); err == nil {
		t.Fatal("required email accepted")
	}
	if err := s.Validate(WithOptional(r, []string{"email"}), nil); err != nil {
		t.Fatal(err)
	}
	if AnySpec(nil, s) != nil || AnySpec(nil) != nil {
		t.Fatal("AnySpec must skip validation when a description is missing")
	}
	a := AnySpec(s, s)
	if a == nil {
		t.Fatal("AnySpec with every description present")
	}
	if err := a.Validate(req("GET", "https://x/nope", ""), nil); err == nil {
		t.Fatal("AnySpec accepted unknown path")
	}
}

// A server URL whose host carries a template variable still yields its path
// prefix, so paths relative to it validate.
func TestServerPathWithVariables(t *testing.T) {
	doc := `{"openapi":"3.0.1","servers":[{"url":"https://{your-domain}.atlassian.net/wiki/api/v2","variables":{"your-domain":{"default":"your-domain"}}}],
	"paths":{"/spaces":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
	s, err := LoadSpec("c", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(req("GET", "https://x/wiki/api/v2/spaces", ""), nil); err != nil {
		t.Fatalf("prefixed path rejected: %v", err)
	}
	if err := s.Validate(req("GET", "https://x/spaces", ""), nil); err != nil {
		t.Fatalf("bare path rejected: %v", err)
	}
	for in, want := range map[string]string{
		"https://{h}/wiki/api/v2/": "/wiki/api/v2", "{scheme}://{h}/a": "/a", "https://h": "", "https://h/": "", "/rest/api": "/rest/api",
	} {
		if got := serverPath(map[string]any{"url": in}); got != want {
			t.Errorf("serverPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLeadingVariableSpansSegments(t *testing.T) {
	const arm = `{"swagger": "2.0", "paths": {
	 "/{scope}/providers/Microsoft.Authorization/roleAssignments": {"get": {"parameters": [{"name": "$filter", "in": "query", "type": "string"}]}},
	 "/{roleId}": {"get": {}},
	 "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments": {"get": {}}
	}}`
	s, err := LoadSpec("arm", []byte(arm))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"https://x/subscriptions/1/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()",
		"https://x/subscriptions/1/providers/Microsoft.Authorization/roleAssignments",
		"https://x/providers/Microsoft.Management/managementGroups/mg/providers/Microsoft.Authorization/roleAssignments",
		"https://x/subscriptions/1/providers/Microsoft.Authorization/roleDefinitions/abc",
	} {
		if err := s.Validate(req("GET", u, ""), nil); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	if err := s.Validate(req("GET", "https://x/subscriptions/1/providers/Microsoft.Authorization/roleAssignments?bogus=1", ""), nil); err == nil {
		t.Error("undeclared query accepted")
	}
}
