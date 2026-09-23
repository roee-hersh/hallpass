// Command hallpass is the permission check service.
//
//	hallpass serve    -config /etc/hallpass/hallpass.yaml
//	hallpass validate -config /etc/hallpass/hallpass.yaml
//	hallpass probe    -config /etc/hallpass/hallpass.yaml [-connection id]
//	hallpass check    -config /etc/hallpass/hallpass.yaml -connection id -user email -action name -resource res
//	hallpass catalog  [integration]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/roee-hersh/hallpass/internal/config"
	"github.com/roee-hersh/hallpass/internal/declog"
	"github.com/roee-hersh/hallpass/internal/engine"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integrations/all"
	"github.com/roee-hersh/hallpass/internal/server"
)

// version is set by the build (-ldflags "-X main.version=...").
var version = "dev"

const defaultConfig = "/etc/hallpass/hallpass.yaml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w *os.File) {
	fmt.Fprintf(w, `hallpass %s - permission check service

Usage:
  hallpass serve    -config FILE [-listen ADDR] [-log-level LEVEL]
  hallpass validate -config FILE
  hallpass probe    -config FILE [-connection ID]
  hallpass check    -config FILE -connection ID -user EMAIL -action NAME -resource RES [-group G]... [-json]
  hallpass catalog  [INTEGRATION]
  hallpass version

Default config: %s
`, version, defaultConfig)
}

func run(args []string, stdout, stderr *os.File) int {
	httpx.Version = version
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stderr)
	case "validate":
		return validate(args[1:], stdout, stderr)
	case "probe":
		return probe(args[1:], stdout, stderr)
	case "check":
		return check(args[1:], stdout, stderr)
	case "catalog":
		return catalog(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func newLogger(level string, w *os.File) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level %q: %w", level, err)
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl})), nil
}

func load(path string, stderr *os.File) (*config.Config, *integration.Registry, bool) {
	reg := all.Registry()
	cfg, err := config.Load(path, reg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, nil, false
	}
	return cfg, reg, true
}

// serveParent is the context serve runs under; a signal or its
// cancellation stops the server. Tests cancel it, since sending the test
// process a signal is not portable.
var serveParent = context.Background()

func serve(args []string, stderr *os.File) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "config file")
	listen := fs.String("listen", "", "listen address (overrides the config)")
	level := fs.String("log-level", "info", "debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger, err := newLogger(*level, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	cfg, _, ok := load(*cfgPath, stderr)
	if !ok {
		return 1
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	dl, err := declog.Open(cfg.DecisionLog)
	if err != nil {
		fmt.Fprintf(stderr, "decision_log: %v\n", err)
		return 1
	}
	defer dl.Close()

	ctx, stop := signal.NotifyContext(serveParent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	eng, err := engine.Build(ctx, cfg, engine.Options{
		Logger:        logger,
		DecisionLog:   dl,
		DecisionCache: cfg.DecisionCache,
		IdentityCache: cfg.IdentityCache,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// Startup probe: warn, never block. One broken upstream must not take
	// down the healthy connections.
	go func() {
		for _, r := range eng.Probe(ctx) {
			if r.Err != nil {
				logger.Warn("probe failed", "connection", r.ID, "integration", r.Integration, "error", r.Err.Error())
				continue
			}
			for _, w := range r.Result.Warnings {
				logger.Warn("probe warning", "connection", r.ID, "integration", r.Integration, "warning", w)
			}
			logger.Info("probe ok", "connection", r.ID, "integration", r.Integration, "summary", r.Result.Summary)
		}
	}()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(eng, cfg.APIKey, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Listen, "connections", len(eng.Connections()), "version", version)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, err)
			return 1
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("shutdown", "error", err.Error())
		}
	}
	return 0
}

func validate(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, _, ok := load(*cfgPath, stderr)
	if !ok {
		return 1
	}
	// Building connections parses credentials and certificates without
	// touching the network.
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if _, err := engine.Build(context.Background(), cfg, engine.Options{Logger: logger}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := cfg.APIKey.Get(); err != nil {
		fmt.Fprintf(stderr, "api_key: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: ok, %d connection(s)\n", *cfgPath, len(cfg.Connections))
	for _, c := range cfg.Connections {
		fmt.Fprintf(stdout, "  %-24s %s\n", c.ID, c.Integration)
	}
	return 0
}

func probe(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "config file")
	only := fs.String("connection", "", "probe only this connection id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, _, ok := load(*cfgPath, stderr)
	if !ok {
		return 1
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	eng, err := engine.Build(context.Background(), cfg, engine.Options{Logger: logger})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var ids []string
	if *only != "" {
		ids = []string{*only}
	}
	failed := 0
	for _, r := range eng.Probe(context.Background(), ids...) {
		if r.Err != nil {
			failed++
			fmt.Fprintf(stdout, "FAIL %-24s %-12s %v\n", r.ID, r.Integration, r.Err)
			continue
		}
		fmt.Fprintf(stdout, "ok   %-24s %-12s %s\n", r.ID, r.Integration, r.Result.Summary)
		for _, w := range r.Result.Warnings {
			fmt.Fprintf(stdout, "     warning: %s\n", w)
		}
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// Exit codes of check. 2 (usage or config error) is shared with the other
// commands; 1 and 3 mirror the decision so that `if hallpass check ...`
// treats unknown as deny, as the API asks callers to.
const (
	exitAllow   = 0
	exitDeny    = 1
	exitUsage   = 2
	exitUnknown = 3
)

// check answers one question from the command line, running the same code
// path as POST /check but in-process: it needs the config file and the
// connection's credential, not a running server or the API key. Caches and
// the decision log are off; a check from the CLI is an operator asking, not
// an agent acting.
func check(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "config file")
	connID := fs.String("connection", "", "connection id from the config")
	user := fs.String("user", "", "email of the user asking")
	action := fs.String("action", "", "action name (see hallpass catalog INTEGRATION)")
	resource := fs.String("resource", "", "resource such as namespace:payments or issue:PAY-123")
	asJSON := fs.Bool("json", false, "print the same JSON as POST /check")
	var groups []string
	fs.Func("group", "group the user belongs to (repeatable)", func(g string) error {
		groups = append(groups, g)
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "check takes flags only, unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return exitUsage
	}
	var missing []string
	for _, f := range []struct{ name, val string }{{"connection", *connID}, {"user", *user}, {"action", *action}, {"resource", *resource}} {
		if f.val == "" {
			missing = append(missing, "-"+f.name)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "check: missing %s\n", strings.Join(missing, ", "))
		fs.Usage()
		return exitUsage
	}
	cfg, _, ok := load(*cfgPath, stderr)
	if !ok {
		return exitUsage
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	eng, err := engine.Build(ctx, cfg, engine.Options{Logger: logger})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	res := eng.Check(ctx, engine.Request{
		User:       *user,
		Groups:     groups,
		Connection: *connID,
		Action:     *action,
		Resource:   *resource,
		Remote:     "cli",
	})
	d := res.Decision
	if *asJSON {
		// Same shape as the HTTP response body.
		_ = json.NewEncoder(stdout).Encode(struct {
			Decision integration.Outcome `json:"decision"`
			Reason   string              `json:"reason"`
		}{d.Outcome, d.Reason()})
	} else {
		fmt.Fprintf(stdout, "%s\n  %s\n", d.Outcome, d.Reason())
	}
	switch d.Outcome {
	case integration.Allow:
		return exitAllow
	case integration.Deny:
		return exitDeny
	default:
		return exitUnknown
	}
}

func catalog(args []string, stdout, stderr *os.File) int {
	reg := all.Registry()
	if len(args) == 0 {
		for _, n := range reg.Names() {
			i, _ := reg.Lookup(n)
			fmt.Fprintf(stdout, "%-18s %d action(s)\n", n, len(i.Actions()))
		}
		return 0
	}
	i, ok := reg.Lookup(args[0])
	if !ok {
		fmt.Fprintf(stderr, "unknown integration %q (known: %s)\n", args[0], strings.Join(reg.Names(), ", "))
		return 1
	}
	fmt.Fprintf(stdout, "integration: %s\n\nconfig keys:\n", i.Name())
	fields := append([]integration.Field(nil), i.Fields()...)
	sort.SliceStable(fields, func(a, b int) bool { return fields[a].Required && !fields[b].Required })
	for _, f := range fields {
		var flags []string
		if f.Required {
			flags = append(flags, "required")
		}
		if f.Secret {
			flags = append(flags, "secret: env:NAME or file:/path")
		}
		if f.Ref != "" {
			flags = append(flags, "id of a "+f.Ref+" connection")
		}
		if f.Default != "" {
			flags = append(flags, "default "+f.Default)
		}
		if len(f.Enum) > 0 {
			flags = append(flags, "one of "+strings.Join(f.Enum, "|"))
		}
		fmt.Fprintf(stdout, "  %-26s %s", f.Name, f.Description)
		if len(flags) > 0 {
			fmt.Fprintf(stdout, " (%s)", strings.Join(flags, "; "))
		}
		fmt.Fprintln(stdout)
	}
	fmt.Fprintf(stdout, "  %-26s %s\n", "ca_file", "PEM file that replaces the system roots (optional)")
	fmt.Fprintf(stdout, "  %-26s %s\n", "tls_server_name", "name verified against the server certificate (optional)")
	fmt.Fprintf(stdout, "  %-26s %s\n", "proxy_url", "http:// or https:// proxy (optional)")
	fmt.Fprintf(stdout, "  %-26s %s\n", "timeout", "per-check budget such as 10s (default 8s)")
	fmt.Fprintln(stdout, "\nactions:")
	for _, a := range i.Actions() {
		fmt.Fprintf(stdout, "  %-40s %s\n", a.Name, a.Description)
	}
	return 0
}
