//go:build live

// Package live runs check cases against real systems. It is opt-in:
//
//	HALLPASS_LIVE_CASES=/path/to/cases.yaml go test -tags live ./test/live/
//
// The cases file names a hallpass config file and a list of expected
// answers (see examples/live-cases.yaml). Every connection in the config is
// probed first. A case whose answer differs fails the test; the decision
// text is printed for every case so an unknown can be understood.
package live

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/roee-hersh/hallpass/internal/config"
	"github.com/roee-hersh/hallpass/internal/engine"
	"github.com/roee-hersh/hallpass/internal/integrations/all"
)

type casesFile struct {
	Config string `yaml:"config"`
	Cases  []struct {
		Name       string   `yaml:"name"`
		Connection string   `yaml:"connection"`
		User       string   `yaml:"user"`
		Groups     []string `yaml:"groups"`
		Action     string   `yaml:"action"`
		Resource   string   `yaml:"resource"`
		Expect     string   `yaml:"expect"` // allow, deny or unknown
		Code       string   `yaml:"code"`   // optional reason code
	} `yaml:"cases"`
}

func TestLive(t *testing.T) {
	path := os.Getenv("HALLPASS_LIVE_CASES")
	if path == "" {
		t.Skip("HALLPASS_LIVE_CASES not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cf casesFile
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	cfgPath := cf.Config
	if !filepath.IsAbs(cfgPath) {
		cfgPath = filepath.Join(filepath.Dir(path), cfgPath)
	}
	cfg, err := config.Load(cfgPath, all.Registry())
	if err != nil {
		t.Fatal(err)
	}
	cfg.DecisionCache = 0
	eng, err := engine.Build(context.Background(), cfg, engine.Options{DecisionCache: 0, IdentityCache: 0})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, p := range eng.Probe(ctx) {
		if p.Err != nil {
			t.Errorf("probe %s (%s): %v", p.ID, p.Integration, p.Err)
			continue
		}
		t.Logf("probe %s (%s): %s", p.ID, p.Integration, p.Result.Summary)
		for _, w := range p.Result.Warnings {
			t.Logf("  warning: %s", w)
		}
	}
	for i, c := range cf.Cases {
		name := c.Name
		if name == "" {
			name = fmt.Sprintf("case-%d", i+1)
		}
		t.Run(name, func(t *testing.T) {
			res := eng.Check(ctx, engine.Request{User: c.User, Groups: c.Groups, Connection: c.Connection, Action: c.Action, Resource: c.Resource})
			got := string(res.Decision.Outcome)
			t.Logf("%s %s %s on %s -> %s (%s)", c.Connection, c.User, c.Action, c.Resource, got, res.Decision.Reason())
			if want := strings.ToLower(strings.TrimSpace(c.Expect)); want != "" && got != want {
				t.Errorf("want %s, got %s: %s", want, got, res.Decision.Reason())
			}
			if c.Code != "" && string(res.Decision.Code) != c.Code {
				t.Errorf("want code %s, got %s", c.Code, res.Decision.Code)
			}
		})
	}
}
