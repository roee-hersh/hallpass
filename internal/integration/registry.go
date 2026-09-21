package integration

import (
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// Registry holds the known integrations by name.
type Registry struct {
	mu    sync.RWMutex
	items map[string]Integration
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

// NewRegistry creates an empty registry.
func NewRegistry() *Registry { return &Registry{items: map[string]Integration{}} }

// Register adds an integration. It validates the name, the field
// declarations and the action table, and panics on a programming error
// because registration happens at init time.
func (r *Registry) Register(i Integration) {
	if err := r.register(i); err != nil {
		panic(err)
	}
}

func (r *Registry) register(i Integration) error {
	name := i.Name()
	if !nameRe.MatchString(name) {
		return fmt.Errorf("integration name %q must match %s", name, nameRe)
	}
	if err := ValidateFields(i.Fields()); err != nil {
		return fmt.Errorf("integration %s: %w", name, err)
	}
	seen := map[string]bool{}
	for _, a := range i.Actions() {
		if err := catalog.ValidateActionName(a.Name); err != nil && !a.Pattern {
			return fmt.Errorf("integration %s: action %q: %w", name, a.Name, err)
		}
		if seen[a.Name] {
			return fmt.Errorf("integration %s: action %q declared twice", name, a.Name)
		}
		seen[a.Name] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.items[name]; dup {
		return fmt.Errorf("integration %s registered twice", name)
	}
	r.items[name] = i
	return nil
}

// Lookup finds an integration by name.
func (r *Registry) Lookup(name string) (Integration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	i, ok := r.items[name]
	return i, ok
}

// Names lists registered integrations, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ns := make([]string, 0, len(r.items))
	for n := range r.items {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return ns
}

// FindAction resolves an action name for an integration: exact match in
// Actions first, then the ActionMatcher if implemented.
func FindAction(i Integration, name string) (catalog.Action, bool) {
	for _, a := range i.Actions() {
		if !a.Pattern && a.Name == name {
			return a, true
		}
	}
	if m, ok := i.(ActionMatcher); ok {
		return m.MatchAction(name)
	}
	return catalog.Action{}, false
}
