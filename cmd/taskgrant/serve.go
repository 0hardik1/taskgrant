package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0hardik1/taskgrant/internal/config"
)

// cmdServe runs the broker: MCP transport per config (or --stdio),
// admin unix socket, optional bearer-authed admin HTTP binding, expiry
// sweeps, and the external anchor timer.
func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "config file path")
	stdio := fs.Bool("stdio", false, "serve MCP over stdio with a fixed agent identity")
	agent := fs.String("agent", "", "fixed agent id for --stdio")
	verbose := fs.Bool("verbose", false, "debug logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	// Logs go to stderr: with --stdio, stdout carries the MCP stream.
	logger := newLogger(stderr, level)
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	a, err := compose(ctx, *configPath, composeOptions{
		stdioAgent: *agent,
		forceStdio: *stdio,
		logger:     logger,
	})
	if err != nil {
		return fail(stderr, "serve: %v", err)
	}
	defer a.Close()

	// Startup posture logs (section 8.7 plus preflight bookkeeping).
	logger.Info("taskgrant broker starting",
		"version", version,
		"transport", a.cfg.Server.Transport,
		"caller_arn", a.identity.ARN,
		"chained", a.identity.Chained,
		"catalog_hash", a.catalog.Current().CatalogHash(),
		"dataset_hash", a.ds.Hash(),
		"config_hash", a.cfg.ConfigHash(),
	)
	if a.identity.Chained {
		logger.Warn("broker runs on session credentials; every mint is role chaining and durations clamp to 3600 seconds")
	}
	warnPreflightNeverPassed(a.cfg, logger)

	if err := a.startAnchor(); err != nil {
		return fail(stderr, "serve: anchor: %v", err)
	}

	// Broker sweeps (pending TTL expiry, active expiry, GC).
	go a.broker.Run(ctx)

	// Admin unix socket.
	errCh := make(chan error, 3)
	if sock := a.cfg.Server.AdminSocket; sock != "" {
		go func() { errCh <- a.admin.ServeUnix(ctx, sock) }()
	} else {
		logger.Warn("server.admin_socket is unset; approvals and the creds helper are unavailable")
	}

	// Optional bearer-authed admin HTTP binding (section 11 step 4),
	// enabled through TASKGRANT_ADMIN_LISTEN + TASKGRANT_ADMIN_TOKEN_SHA256.
	if addr := os.Getenv("TASKGRANT_ADMIN_LISTEN"); addr != "" {
		go func() { errCh <- a.admin.ServeTCP(ctx, addr) }()
	}

	// MCP transport.
	switch a.cfg.Server.Transport {
	case config.TransportStdio:
		go func() { errCh <- a.mcp.ServeStdio(ctx) }()
	case config.TransportHTTP:
		handler, herr := a.mcp.HTTPHandler()
		if herr != nil {
			return fail(stderr, "serve: %v", herr)
		}
		srv := &http.Server{
			Addr:              a.cfg.Server.Listen,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			logger.Info("mcp http listening", "addr", a.cfg.Server.Listen)
			errCh <- srv.ListenAndServe()
		}()
		go func() {
			<-ctx.Done()
			shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shCancel()
			_ = srv.Shutdown(shCtx)
		}()
	default:
		return fail(stderr, "serve: unknown transport %q", a.cfg.Server.Transport)
	}

	select {
	case <-ctx.Done():
		logger.Info("taskgrant broker stopping")
		return 0
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return fail(stderr, "serve: %v", err)
		}
		return 0
	}
}

// preflightMarkerPath is the file recording per-profile preflight
// passes, next to the decision log.
func preflightMarkerPath(cfg *config.Config) string {
	return cfg.Log.Path + ".preflight.json"
}

// readPreflightMarker loads the marker file; missing files yield an
// empty map.
func readPreflightMarker(cfg *config.Config) map[string]time.Time {
	out := map[string]time.Time{}
	data, err := os.ReadFile(preflightMarkerPath(cfg))
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, &out)
	return out
}

// writePreflightMarker records a preflight pass for the profiles.
func writePreflightMarker(cfg *config.Config, passed []string) error {
	marker := readPreflightMarker(cfg)
	now := time.Now().UTC()
	for _, p := range passed {
		marker[p] = now
	}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	tmp := preflightMarkerPath(cfg) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, preflightMarkerPath(cfg))
}

// warnPreflightNeverPassed emits the section 8.6 startup warning for
// every configured profile with no recorded preflight pass.
func warnPreflightNeverPassed(cfg *config.Config, logger *slog.Logger) {
	marker := readPreflightMarker(cfg)
	for _, name := range cfg.ProfileNames() {
		if _, ok := marker[name]; !ok {
			logger.Warn("preflight has never passed for this profile; run `taskgrant preflight` before agents arrive",
				"profile", name)
		}
	}
}

// jsonOut writes v as indented JSON to w.
func jsonOut(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(w, err)
		return 1
	}
	return 0
}
