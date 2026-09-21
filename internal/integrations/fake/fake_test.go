package fake

import (
	"context"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

func conn(t *testing.T, fail string) integration.Connection {
	t.Helper()
	s := integration.NewSettings("f", "fake", map[string]string{"users": "u@x.com, U2@x.com", "admins": "a@x.com", "fail": fail}, nil)
	c, err := Integration{}.New(context.Background(), s, integration.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func check(t *testing.T, c integration.Connection, email, action, resource string) integration.Decision {
	t.Helper()
	ctx := context.Background()
	id, err := c.ResolveIdentity(ctx, integration.User{Email: email})
	if err != nil {
		return integration.ToDecision(err)
	}
	res, err := catalog.ParseResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	act, _ := integration.FindAction(Integration{}, action)
	d, err := c.Check(ctx, integration.CheckRequest{User: integration.User{Email: email}, Identity: id, Action: act, ActionName: action, Resource: res})
	if err != nil {
		return integration.ToDecision(err)
	}
	return d
}

func TestAction_thing_read_allow(t *testing.T) {
	if d := check(t, conn(t, "none"), "u2@x.com", "thing.read", "thing:1"); d.Outcome != integration.Allow {
		t.Fatal(d)
	}
}

func TestAction_thing_read_deny(t *testing.T) {
	if d := check(t, conn(t, "none"), "nobody@x.com", "thing.read", "thing:1"); d.Code != integration.CodeUserNotFound || d.Outcome != integration.Deny {
		t.Fatal(d)
	}
}

func TestAction_thing_write_allow(t *testing.T) {
	if d := check(t, conn(t, "none"), "a@x.com", "thing.write", "thing:1"); d.Outcome != integration.Allow {
		t.Fatal(d)
	}
}

func TestAction_thing_write_deny(t *testing.T) {
	if d := check(t, conn(t, "none"), "u@x.com", "thing.write", "thing:1"); d.Code != integration.CodeDenied {
		t.Fatal(d)
	}
}

func TestAction_thing_admin_allow(t *testing.T) {
	if d := check(t, conn(t, "none"), "a@x.com", "thing.admin", "thing:1"); d.Outcome != integration.Allow {
		t.Fatal(d)
	}
}

func TestAction_thing_admin_deny(t *testing.T) {
	if d := check(t, conn(t, "none"), "u@x.com", "thing.admin", "thing:1"); d.Code != integration.CodeDenied {
		t.Fatal(d)
	}
}

func TestUnknowns(t *testing.T) {
	c := conn(t, "none")
	if d := check(t, c, "ambiguous@x.com", "thing.read", "thing:1"); d.Code != integration.CodeUserAmbiguous {
		t.Error(d)
	}
	if d := check(t, c, "u@x.com", "thing.read", "thing:hidden"); d.Code != integration.CodeResourceNotVisible {
		t.Error(d)
	}
	if d := check(t, c, "u@x.com", "thing.read", "thing:broken"); d.Code != integration.CodeUnsupported {
		t.Error(d)
	}
	if d := check(t, c, "u@x.com", "thing.read", "other:1"); d.Code != integration.CodeInvalidRequest {
		t.Error(d)
	}
	if d := check(t, conn(t, "upstream_timeout"), "u@x.com", "thing.read", "thing:1"); d.Code != integration.CodeUpstreamTimeout {
		t.Error(d)
	}
	if _, err := conn(t, "credential_rejected").Probe(context.Background()); err == nil {
		t.Error("probe should fail")
	}
	r, err := c.Probe(context.Background())
	if err != nil || r.Summary == "" {
		t.Error(r, err)
	}
}
