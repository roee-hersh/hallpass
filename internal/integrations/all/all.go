// Package all registers every integration. It is the one place that lists
// them, so a build without an integration is one deleted line.
package all

import (
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integrations/argocd"
	"github.com/roee-hersh/hallpass/internal/integrations/aws"
	"github.com/roee-hersh/hallpass/internal/integrations/bitbucket"
	"github.com/roee-hersh/hallpass/internal/integrations/confluence"
	"github.com/roee-hersh/hallpass/internal/integrations/databricks"
	"github.com/roee-hersh/hallpass/internal/integrations/fake"
	"github.com/roee-hersh/hallpass/internal/integrations/github"
	"github.com/roee-hersh/hallpass/internal/integrations/gitlab"
	"github.com/roee-hersh/hallpass/internal/integrations/googlecloud"
	"github.com/roee-hersh/hallpass/internal/integrations/googleworkspace"
	"github.com/roee-hersh/hallpass/internal/integrations/jira"
	"github.com/roee-hersh/hallpass/internal/integrations/kubernetes"
	"github.com/roee-hersh/hallpass/internal/integrations/linear"
	"github.com/roee-hersh/hallpass/internal/integrations/microsoft365"
	"github.com/roee-hersh/hallpass/internal/integrations/salesforce"
	"github.com/roee-hersh/hallpass/internal/integrations/slack"
)

// Registry returns a registry with every integration.
func Registry() *integration.Registry {
	r := integration.NewRegistry()
	r.Register(fake.Integration{})
	r.Register(kubernetes.Integration{})
	r.Register(argocd.Integration{})
	r.Register(aws.Integration{})
	r.Register(github.Integration{})
	r.Register(gitlab.Integration{})
	r.Register(bitbucket.Integration{})
	r.Register(jira.Integration{})
	r.Register(confluence.Integration{})
	r.Register(slack.Integration{})
	r.Register(salesforce.Integration{})
	r.Register(microsoft365.Integration{})
	r.Register(googleworkspace.Integration{})
	r.Register(linear.Integration{})
	r.Register(databricks.Integration{})
	r.Register(googlecloud.Integration{})
	return r
}
