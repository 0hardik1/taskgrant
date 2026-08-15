package main

// compose.go wires the whole broker with constructor injection: config
// in, a runnable app out. Every cross-package adapter is created here
// and nowhere else.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/0hardik1/taskgrant/internal/adminapi"
	"github.com/0hardik1/taskgrant/internal/approvals"
	"github.com/0hardik1/taskgrant/internal/broker"
	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/guardrails"
	"github.com/0hardik1/taskgrant/internal/identity"
	"github.com/0hardik1/taskgrant/internal/mcpserver"
	"github.com/0hardik1/taskgrant/internal/revoke"
	"github.com/0hardik1/taskgrant/internal/store"
	"github.com/0hardik1/taskgrant/internal/stsmint"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
	"github.com/0hardik1/taskgrant/internal/synth/compile"
	"github.com/0hardik1/taskgrant/internal/synth/match"
	"github.com/0hardik1/taskgrant/internal/synth/synthesizer"
)

// app is the fully wired broker process.
type app struct {
	cfg        *config.Config
	logger     *slog.Logger
	ds         *dataset.Dataset
	catalog    *catalog.Store
	store      *store.Store
	approvals  *approvals.Manager
	minter     *stsmint.Minter
	identity   stsmint.BrokerIdentity
	broker     *broker.Broker
	mcp        *mcpserver.Server
	admin      *adminapi.Server
	metrics    *adminapi.Metrics
	revoker    *revoke.Revoker
	anchorStop func()
}

// loadCore loads config, dataset, and catalog: the shared foundation
// several commands need without a full broker.
func loadCore(configPath string) (*config.Config, *dataset.Dataset, *catalog.Snapshot, error) {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return nil, nil, nil, err
	}
	ds, err := dataset.Load(cfg.Synth.DatasetPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load dataset: %w", err)
	}
	snap, err := catalog.Load(cfg.Synth.CatalogPath, ds,
		catalog.WithExtraDeniedServices(cfg.Guardrails.ExtraDenyServices...))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load catalog: %w", err)
	}
	return cfg, ds, snap, nil
}

// composeOptions tunes compose for the serve command.
type composeOptions struct {
	// stdioAgent overrides server.default_agent for --stdio --agent.
	stdioAgent string
	// forceStdio forces the stdio transport regardless of config.
	forceStdio bool
	logger     *slog.Logger
}

// compose builds the app. Callers own the returned app's Close.
func compose(ctx context.Context, configPath string, opts composeOptions) (*app, error) {
	logger := opts.logger
	if logger == nil {
		logger = slog.Default()
	}

	cfg, ds, snap, err := loadCore(configPath)
	if err != nil {
		return nil, err
	}
	if opts.forceStdio {
		cfg.Server.Transport = config.TransportStdio
		if opts.stdioAgent != "" {
			cfg.Server.DefaultAgent = opts.stdioAgent
		}
		if cfg.Server.DefaultAgent == "" {
			return nil, fmt.Errorf("stdio transport requires --agent or server.default_agent")
		}
		if _, ok := cfg.Agents[cfg.Server.DefaultAgent]; !ok {
			return nil, fmt.Errorf("agent %q is not configured", cfg.Server.DefaultAgent)
		}
	}

	catStore := catalog.NewStore(snap)

	// Store, approvals, metrics.
	st, err := store.Open(store.Options{
		Path:            cfg.Log.Path,
		MirrorJSONLPath: cfg.Log.MirrorJSONL,
		Logger:          logger,
	})
	if err != nil {
		return nil, err
	}
	appr, err := approvals.New(st, time.Duration(cfg.Approvals.PendingTTLSeconds)*time.Second,
		approvals.Options{Logger: logger})
	if err != nil {
		st.Close()
		return nil, err
	}
	metrics := adminapi.NewMetrics()

	// STS minter: the only place the parent credential chain loads (I4).
	minter, err := stsmint.New(ctx, stsmint.Options{
		Region:      cfg.AWS.STSRegion,
		EndpointURL: cfg.AWS.EndpointURL,
		Logger:      logger,
	})
	if err != nil {
		st.Close()
		return nil, err
	}
	callerID, err := minter.CallerIdentity(ctx)
	if err != nil {
		logger.Warn("startup caller identity check failed; chaining detection unavailable", "err", err)
	}

	// Guardrail evaluator, shared implementation used twice (section 6).
	evaluator, err := guardrails.New(ds, guardrails.Config{
		AllowedAccessLevels:      cfg.Guardrails.AccessLevels,
		ExtraDenyServices:        cfg.Guardrails.ExtraDenyServices,
		ResourceAllowlist:        snap.ResourcePatterns(),
		Accounts:                 cfg.AWS.Accounts,
		GlobalMaxDurationSeconds: cfg.AWS.MaxDurationSeconds,
	})
	if err != nil {
		st.Close()
		return nil, err
	}

	// Compiler and synthesizer with the consumer-side adapters.
	compiler, err := compile.New(ds)
	if err != nil {
		st.Close()
		return nil, err
	}
	classifier, err := match.NewClassifierFromConfig(cfg.Synth.LLM)
	if err != nil {
		st.Close()
		return nil, err
	}
	synthImpl, err := synthesizer.New(synthesizer.Deps{
		Catalog: catalogAdapter{store: catStore},
		Compiler: compilerAdapter{
			store:         catStore,
			compiler:      compiler,
			region:        cfg.AWS.STSRegion,
			accounts:      cfg.AWS.Accounts,
			maxPolicyArns: offloadARNBudget(cfg),
		},
		Guardrails:       synthGuardrailAdapter{evaluator: evaluator, store: catStore, chained: callerID.Chained},
		Params:           paramsAdapter{store: catStore},
		Cache:            synthesizer.NewMemoryCache(0),
		Classifier:       classifier,
		FirstUse:         firstUseFunc(st),
		FirstUseApproval: cfg.Guardrails.FirstUseApproval,
		DatasetHash:      ds.Hash(),
		ConfigHash:       cfg.ConfigHash(),
	})
	if err != nil {
		st.Close()
		return nil, err
	}

	// Optional revoker.
	var revoker *revoke.Revoker
	if cfg.Revocation.Enabled {
		writer, werr := revoke.NewIAMPolicyWriter(revoke.IAMWriterOptions{
			EndpointURL: cfg.AWS.EndpointURL,
			Region:      cfg.AWS.STSRegion,
			Credentials: store.EnvCredentialsProvider{},
		})
		if werr != nil {
			st.Close()
			return nil, werr
		}
		revoker, werr = revoke.New(writer, revoke.Options{Logger: logger})
		if werr != nil {
			st.Close()
			return nil, werr
		}
	}

	// The broker core.
	var revokerIface broker.GrantRevoker
	if revoker != nil {
		revokerIface = revoker
	}
	core, err := broker.New(broker.Deps{
		Config:    cfg,
		Synth:     synthImpl,
		Evaluator: evaluator,
		Approvals: appr,
		Minter:    minter,
		Log:       st,
		Catalog:   catStore,
		Dataset:   ds,
		Revoker:   revokerIface,
		Metrics:   metrics,
		Chained:   callerID.Chained,
		Logger:    logger,
	})
	if err != nil {
		st.Close()
		return nil, err
	}

	// MCP surface.
	mcpOpts := mcpserver.Options{
		MaxWaitSeconds:       cfg.Server.MaxWaitSeconds,
		CredentialRedelivery: cfg.Server.CredentialRedelivery,
		Version:              version,
		Logger:               logger,
	}
	if cfg.Server.Transport == config.TransportStdio {
		mcpOpts.FixedAgentID = cfg.Server.DefaultAgent
	} else {
		registry, rerr := identity.NewRegistry(cfg)
		if rerr != nil {
			st.Close()
			return nil, rerr
		}
		mcpOpts.Verifier = registry
	}
	mcpSrv, err := mcpserver.New(core, mcpOpts)
	if err != nil {
		st.Close()
		return nil, err
	}

	// Admin surface: unix socket always, bearer HTTP when configured
	// through the environment (see serve.go).
	bridge := broker.AdminBridge{B: core}
	audit := broker.AuditBridge{Store: st}
	var bearer adminapi.AdminTokenVerifier
	if hash := os.Getenv("TASKGRANT_ADMIN_TOKEN_SHA256"); hash != "" {
		principal := os.Getenv("TASKGRANT_ADMIN_PRINCIPAL")
		if principal == "" {
			principal = "admin-api"
		}
		bearer = adminapi.StaticTokenVerifier{PrincipalName: principal, SHA256Hex: hash}
	}
	var adminRevoker adminapi.Revoker
	if revoker != nil {
		adminRevoker = bridge
	}
	adminSrv, err := adminapi.New(adminapi.Deps{
		Approvals: bridge,
		Audit:     audit,
		Revoker:   adminRevoker,
		Ready:     core,
		Creds:     bridge,
		Metrics:   metrics,
		Logger:    logger,
	}, adminapi.Options{
		Bearer:         bearer,
		MultiAgentHTTP: cfg.Server.Transport == config.TransportHTTP && len(cfg.Agents) > 1,
	})
	if err != nil {
		st.Close()
		return nil, err
	}

	a := &app{
		cfg:       cfg,
		logger:    logger,
		ds:        ds,
		catalog:   catStore,
		store:     st,
		approvals: appr,
		minter:    minter,
		identity:  callerID,
		broker:    core,
		mcp:       mcpSrv,
		admin:     adminSrv,
		metrics:   metrics,
		revoker:   revoker,
	}
	return a, nil
}

// startAnchor starts the external log anchor loop when configured
// (section 9.3), reporting successes into the metrics registry.
func (a *app) startAnchor() error {
	ac := a.cfg.Log.Anchor
	if ac == nil {
		return nil
	}
	key := []byte(os.Getenv("TASKGRANT_ANCHOR_HMAC_KEY"))
	if len(key) == 0 {
		a.logger.Warn("TASKGRANT_ANCHOR_HMAC_KEY is unset; deriving the checkpoint key from the config hash " +
			"(anchor destination immutability remains the primary tamper evidence)")
		key = []byte("taskgrant/anchor/" + a.cfg.ConfigHash())
	}
	var (
		anchorer store.Anchorer
		err      error
	)
	switch ac.Type {
	case config.AnchorS3ObjectLock:
		anchorer, err = store.NewS3ObjectLockAnchorer(store.S3AnchorOptions{
			Bucket:      ac.Bucket,
			Region:      a.cfg.AWS.STSRegion,
			EndpointURL: a.cfg.AWS.EndpointURL,
			Credentials: store.EnvCredentialsProvider{},
		})
	case config.AnchorCloudWatchLogs:
		anchorer, err = store.NewCloudWatchLogsAnchorer(store.CloudWatchLogsAnchorOptions{
			LogGroup:    ac.LogGroup,
			LogStream:   ac.LogStream,
			Region:      a.cfg.AWS.STSRegion,
			EndpointURL: a.cfg.AWS.EndpointURL,
			Credentials: store.EnvCredentialsProvider{},
		})
	default:
		return fmt.Errorf("unknown anchor type %q", ac.Type)
	}
	if err != nil {
		return err
	}
	stop, err := a.store.StartAnchorLoop(metricAnchorer{next: anchorer, metrics: a.metrics},
		ac.Interval.Std(), key)
	if err != nil {
		return err
	}
	a.anchorStop = stop
	return nil
}

// metricAnchorer decorates an Anchorer with anchor-freshness metrics.
type metricAnchorer struct {
	next    store.Anchorer
	metrics *adminapi.Metrics
}

func (m metricAnchorer) Anchor(ctx context.Context, cp store.Checkpoint) error {
	if err := m.next.Anchor(ctx, cp); err != nil {
		return err
	}
	m.metrics.SetAnchorSuccess(time.Now())
	return nil
}

// Close releases everything the app owns.
func (a *app) Close() {
	if a.anchorStop != nil {
		a.anchorStop()
	}
	if a.revoker != nil {
		a.revoker.Close()
	}
	if a.store != nil {
		a.store.Close()
	}
}

// firstUseFunc builds the durable first-use predicate (invariant I5):
// a pair counts as first use until a mint or an approval marked it
// approved.
func firstUseFunc(st *store.Store) match.FirstUseFunc {
	return func(agentID, capabilityID string) (bool, error) {
		seen, approved, err := st.FirstUseSeen(context.Background(), agentID, capabilityID)
		if err != nil {
			return true, err
		}
		return !(seen && approved), nil
	}
}

// offloadARNBudget computes how many PolicyArns slots the reduction
// ladder may use: the STS ceiling of 10 minus the largest profile
// static ceiling, never below 1.
func offloadARNBudget(cfg *config.Config) int {
	maxStatic := 0
	for _, p := range cfg.Profiles {
		if len(p.PolicyARNs) > maxStatic {
			maxStatic = len(p.PolicyARNs)
		}
	}
	budget := compile.DefaultMaxPolicyArns - maxStatic
	if budget < 1 {
		budget = 1
	}
	return budget
}
