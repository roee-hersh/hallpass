// Package all registers every integration. It is the one place that lists
// them, so a build without an integration is one deleted line.
package all

import (
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integrations/argocd"
	"github.com/roee-hersh/hallpass/internal/integrations/fake"
	"github.com/roee-hersh/hallpass/internal/integrations/kubernetes"
)

// Registry returns a registry with every integration.
func Registry() *integration.Registry {
	r := integration.NewRegistry()
	r.Register(fake.Integration{})
	r.Register(kubernetes.Integration{})
	r.Register(argocd.Integration{})
	return r
}
