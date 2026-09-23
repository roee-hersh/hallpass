package catalog

import "testing"

func TestParseResource(t *testing.T) {
	cases := []struct {
		in      string
		typ, id string
		q       map[string]string
		wantErr bool
	}{
		{in: "repo:acme/api", typ: "repo", id: "acme/api"},
		{in: "repo:acme/api@main", typ: "repo", id: "acme/api@main"},
		{in: "global", typ: "global"},
		{in: "nonresource:/metrics", typ: "nonresource", id: "/metrics"},
		{in: "namespace:payments?resource=deployments.apps&name=api", typ: "namespace", id: "payments", q: map[string]string{"resource": "deployments.apps", "name": "api"}},
		{in: "cluster?resource=nodes", typ: "cluster", q: map[string]string{"resource": "nodes"}},
		{in: "issue:OPS-123", typ: "issue", id: "OPS-123"},
		{in: "arn:aws:s3:::bucket/key", typ: "arn", id: "aws:s3:::bucket/key"},
		{in: "", wantErr: true},
		{in: "Repo:x", wantErr: true},
		{in: "repo:x\n", wantErr: true},
		{in: "ns:x?resource=a&resource=b", wantErr: true},
		{in: "ns:x?Bad=1", wantErr: true},
		{in: "ns:x?%zz", wantErr: true},
		{in: "ns:x?k=%0A", wantErr: true},
		{in: "ns:x?k=%C2%85", wantErr: true},
		{in: "ns:x\u0085y", wantErr: true},
		{in: "ns:x?k=caf%C3%A9", typ: "ns", id: "x", q: map[string]string{"k": "café"}},
	}
	for _, c := range cases {
		r, err := ParseResource(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if r.Type != c.typ || r.ID != c.id {
			t.Errorf("%q: got %q %q", c.in, r.Type, r.ID)
		}
		for k, v := range c.q {
			if r.Q(k) != v {
				t.Errorf("%q: q[%s]=%q", c.in, k, r.Q(k))
			}
		}
	}
}

func TestSplitBranch(t *testing.T) {
	b, br := SplitBranch("acme/webapp@main")
	if b != "acme/webapp" || br != "main" {
		t.Fatal(b, br)
	}
	b, br = SplitBranch("acme/webapp")
	if b != "acme/webapp" || br != "" {
		t.Fatal(b, br)
	}
}

func TestValidateActionName(t *testing.T) {
	for _, ok := range []string{"repo.push", "raw:create:deployments.apps/scale", "BROWSE_PROJECTS", "app.action/apps/Deployment/restart", "raw:s3:PutObject", "raw:iam:*"} {
		if err := ValidateActionName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".x", "a b", "a\n", "a;b"} {
		if err := ValidateActionName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
