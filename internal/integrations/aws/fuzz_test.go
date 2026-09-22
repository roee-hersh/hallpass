package aws

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseResource: an accepted resource is "*" or an ARN in the
// connection's partition; parseRaw only yields <service>:<Action>.
func FuzzParseResource(f *testing.F) {
	for _, s := range [][2]string{
		{"raw:s3:GetObject", "arn:aws:s3:::bucket/key"},
		{"raw:iam:*", "all"},
		{"raw:s3:GetObject", "arn:aws-cn:s3:::bucket"},
		{"raw:s3:GetObject", "arn:aws:s3:::bucket?x=1"},
		{"raw:s3:Get Object", "all:x"},
		{"raw:s3", "arn:aws:iam::123456789012:role/x"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		if act, err := resolveAction(action); err == nil {
			if !rawActionRe.MatchString(act) {
				t.Fatalf("unvalidated action %q", act)
			}
			if strings.HasPrefix(action, "raw:") && act != strings.TrimPrefix(action, "raw:") {
				t.Fatalf("raw action %q changed to %q", action, act)
			}
		}
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		arn, err := parseResource(res, "aws")
		if err != nil {
			return
		}
		if arn == "*" {
			if res.Type != "all" {
				t.Fatalf("* from %q", resource)
			}
			return
		}
		if !arnRe.MatchString(arn) || arnField(arn, 1) != "aws" || arn != res.Raw {
			t.Fatalf("unvalidated arn %q from %q", arn, resource)
		}
		if len(arnField(arn, 5)) > maxARNResource {
			t.Fatalf("resource field too long: %d", len(arnField(arn, 5)))
		}
	})
}
