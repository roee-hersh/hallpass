// Package all registers every integration. It is the one place that lists
// them, so a build without an integration is one deleted line.
package all

import (
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integrations/fake"
)

// Registry returns a registry with every integration.
func Registry() *integration.Registry {
	r := integration.NewRegistry()
	r.Register(fake.Integration{})
	return r
}
