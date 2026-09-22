package aws

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// alias is a named action that expands to one IAM action.
type alias struct {
	name, desc, action string
}

var aliasList = []alias{
	{name: "s3.read", desc: "read an object (s3:GetObject)", action: "s3:GetObject"},
	{name: "s3.write", desc: "write an object (s3:PutObject)", action: "s3:PutObject"},
	{name: "s3.list", desc: "list a bucket (s3:ListBucket)", action: "s3:ListBucket"},
	{name: "ec2.stop", desc: "stop an instance (ec2:StopInstances)", action: "ec2:StopInstances"},
	{name: "ec2.start", desc: "start an instance (ec2:StartInstances)", action: "ec2:StartInstances"},
	{name: "ec2.terminate", desc: "terminate an instance (ec2:TerminateInstances)", action: "ec2:TerminateInstances"},
	{name: "lambda.invoke", desc: "invoke a function (lambda:InvokeFunction)", action: "lambda:InvokeFunction"},
	{name: "iam.passrole", desc: "pass a role to a service (iam:PassRole)", action: "iam:PassRole"},
	{name: "secretsmanager.read", desc: "read a secret value (secretsmanager:GetSecretValue)", action: "secretsmanager:GetSecretValue"},
	{name: "ssm.session", desc: "start a Session Manager session (ssm:StartSession)", action: "ssm:StartSession"},
	{name: "sts.assume", desc: "assume a role (sts:AssumeRole)", action: "sts:AssumeRole"},
	{name: "rds.delete", desc: "delete a database instance (rds:DeleteDBInstance)", action: "rds:DeleteDBInstance"},
	{name: "eks.describe", desc: "describe a cluster (eks:DescribeCluster)", action: "eks:DescribeCluster"},
}

var aliases = func() map[string]alias {
	m := map[string]alias{}
	for _, a := range aliasList {
		m[a.name] = a
	}
	return m
}()

// rawActionRe is the part after "raw:": <service>:<Action>, e.g. s3:GetObject or iam:*.
var rawActionRe = regexp.MustCompile(`^[a-z0-9-]+:[A-Za-z0-9*]+$`)

// arnRe is an ARN in one of the three partitions. The account field is empty
// or exactly 12 digits; the resource part is free-form, at most
// maxARNResource bytes (Go's regexp caps repeat counts below that, so the
// length is checked apart).
var arnRe = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):[a-z0-9-]*:[a-z0-9-]*:([0-9]{12})?:.+$`)

const maxARNResource = 2000

// Actions of the aws integration.
func (Integration) Actions() []catalog.Action {
	acts := []catalog.Action{
		{
			Name:        "raw:<service>:<Action>",
			Pattern:     true,
			Description: "any IAM action, e.g. raw:s3:GetObject, raw:ec2:TerminateInstances, raw:iam:*",
		},
	}
	for _, a := range aliasList {
		acts = append(acts, catalog.Action{Name: a.name, Description: a.desc})
	}
	return acts
}

// MatchAction accepts raw:<service>:<Action>.
func (Integration) MatchAction(name string) (catalog.Action, bool) {
	if _, err := parseRaw(name); err != nil {
		return catalog.Action{}, false
	}
	return catalog.Action{Name: name, Pattern: true, Description: "raw IAM action"}, true
}

// parseRaw returns the IAM action named by raw:<service>:<Action>.
func parseRaw(name string) (string, error) {
	rest, ok := strings.CutPrefix(name, "raw:")
	if !ok {
		return "", errors.New("raw action must be raw:<service>:<Action>, e.g. raw:s3:GetObject")
	}
	if !rawActionRe.MatchString(rest) {
		return "", fmt.Errorf("action %q after raw: must be <service>:<Action> such as s3:GetObject", rest)
	}
	return rest, nil
}

// resolveAction maps the caller's action name to one IAM action.
func resolveAction(name string) (string, error) {
	if strings.HasPrefix(name, "raw:") {
		return parseRaw(name)
	}
	a, ok := aliases[name]
	if !ok {
		return "", fmt.Errorf("unknown action %q", name)
	}
	return a.action, nil
}

// parseResource returns the resource ARN to simulate against, or "*".
//
//	arn:aws:s3:::bucket/key   the ARN itself (catalog.ParseResource splits it
//	                          at the first colon; the raw string is used)
//	all                       every resource ("*")
func parseResource(res catalog.Resource, partition string) (string, error) {
	switch res.Type {
	case "all":
		if res.ID != "" || len(res.Query) > 0 {
			return "", errors.New(`resource "all" takes no id or query`)
		}
		return "*", nil
	case "arn":
		if len(res.Query) > 0 {
			return "", errors.New("an ARN resource takes no ?query; ARNs are used verbatim")
		}
		arn := res.Raw
		if !arnRe.MatchString(arn) || len(arnField(arn, 5)) > maxARNResource {
			return "", fmt.Errorf("resource %q is not an ARN of the form arn:<partition>:<service>:<region>:<account>:<resource>", arn)
		}
		if p := arnField(arn, 1); p != partition {
			return "", fmt.Errorf("resource ARN is in partition %s but the connection is in %s", p, partition)
		}
		return arn, nil
	default:
		return "", fmt.Errorf("resource type %q; use an ARN (arn:aws:...) or all", res.Type)
	}
}

// arnField returns the i-th colon-separated field of an ARN (0 = "arn",
// 1 = partition, 2 = service, 3 = region, 4 = account, 5 = resource).
func arnField(arn string, i int) string {
	parts := strings.SplitN(arn, ":", 6)
	if i >= len(parts) {
		return ""
	}
	return parts[i]
}
