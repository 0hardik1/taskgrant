package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0hardik1/taskgrant/internal/domain"
	"github.com/0hardik1/taskgrant/internal/identity"
)

// Defaults for tunable options.
const (
	defaultMaxWaitSeconds = 60
	defaultPollPerMinute  = 30
	defaultPollBurst      = 10
	serverName            = "taskgrant"
)

// BearerVerifier verifies a presented bearer token and returns the
// verified identity. *identity.Registry satisfies it; a v2 OIDC
// verifier swaps in behind the same interface.
type BearerVerifier interface {
	VerifyToken(presented string) (identity.TokenInfo, error)
}

// Options tunes the MCP server. Zero values take the documented
// defaults.
type Options struct {
	// FixedAgentID pins the identity for the stdio transport (section
	// 4.3: identity fixed at startup, the broker refuses to start
	// without one). Must be empty for the HTTP transport.
	FixedAgentID string
	// Verifier authenticates bearer tokens on the HTTP transport.
	// Required for HTTPHandler.
	Verifier BearerVerifier
	// MaxWaitSeconds caps request_grant.wait_seconds (config
	// server.max_wait_seconds). Default 60.
	MaxWaitSeconds int
	// CredentialRedelivery mirrors config server.credential_redelivery.
	// Default false: credentials cross the boundary exactly once.
	CredentialRedelivery bool
	// PollPerMinute is the get_grant poll budget per agent per minute
	// (config-tunable). Default 30; negative disables limiting.
	PollPerMinute float64
	// PollBurst is the poll bucket burst. Default 10.
	PollBurst int
	// Version is the reported server version.
	Version string
	// Logger receives internal detail that never crosses the MCP
	// boundary. Default slog.Default().
	Logger *slog.Logger
}

// Server is the MCP-facing surface of taskgrant: five tools, two
// transports, one injected broker.
type Server struct {
	broker    Broker
	opts      Options
	logger    *slog.Logger
	limiter   *pollLimiter
	delivered *deliveryTracker
	mcp       *mcp.Server
}

// New builds a Server and registers the five tools of section 4.2.
func New(b Broker, opts Options) (*Server, error) {
	if b == nil {
		return nil, errors.New("mcpserver: nil broker")
	}
	if opts.FixedAgentID != "" {
		if err := domain.ValidateAgentID(opts.FixedAgentID); err != nil {
			return nil, fmt.Errorf("mcpserver: fixed agent: %w", err)
		}
	}
	if opts.MaxWaitSeconds < 0 {
		return nil, fmt.Errorf("mcpserver: negative MaxWaitSeconds %d", opts.MaxWaitSeconds)
	}
	if opts.MaxWaitSeconds == 0 {
		opts.MaxWaitSeconds = defaultMaxWaitSeconds
	}
	if opts.PollPerMinute == 0 {
		opts.PollPerMinute = defaultPollPerMinute
	}
	if opts.PollBurst <= 0 {
		opts.PollBurst = defaultPollBurst
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}

	s := &Server{
		broker:    b,
		opts:      opts,
		logger:    opts.Logger,
		limiter:   newPollLimiter(opts.PollPerMinute, opts.PollBurst),
		delivered: newDeliveryTracker(),
	}

	srv := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: opts.Version}, nil)
	mcp.AddTool(srv, &mcp.Tool{
		Name: "request_grant",
		Description: "Request short-lived AWS credentials for one declared task. " +
			"Returns credentials, a pending approval, a structured clarification, or a denial.",
	}, s.handleRequestGrant)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_grant",
		Description: "Poll the current state of one of your grants by grant_id.",
	}, s.handleGetGrant)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "explain_grant",
		Description: "Explain the decision record of one of your grants: matched capabilities, guardrail verdicts, final policy, outcome.",
	}, s.handleExplainGrant)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_capabilities",
		Description: "List your profiles and the capability catalog entries you can request.",
	}, s.handleListCapabilities)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "release_grant",
		Description: "Record that the task behind a grant ended: succeeded, failed, or abandoned.",
	}, s.handleReleaseGrant)
	s.mcp = srv
	return s, nil
}

// MCPServer exposes the underlying SDK server for integration wiring
// and tests.
func (s *Server) MCPServer() *mcp.Server { return s.mcp }

// ServeStdio runs the stdio transport with the identity fixed at
// startup. It refuses to run without one (section 4.3).
func (s *Server) ServeStdio(ctx context.Context) error {
	if s.opts.FixedAgentID == "" {
		return errors.New("mcpserver: stdio transport requires a fixed agent identity (server.default_agent)")
	}
	s.logger.Info("mcpserver: serving stdio", "agent", s.opts.FixedAgentID)
	return s.mcp.Run(ctx, &mcp.StdioTransport{})
}

// HTTPHandler returns the streamable HTTP surface: /mcp behind the
// SDK's RequireBearerToken middleware with the injected verifier. The
// verified agent id lands in TokenInfo.UserID, which the SDK binds to
// the MCP session (anti-hijack, section 4.3).
func (s *Server) HTTPHandler() (http.Handler, error) {
	if s.opts.FixedAgentID != "" {
		return nil, errors.New("mcpserver: the HTTP transport authenticates per request; do not set a fixed agent")
	}
	if s.opts.Verifier == nil {
		return nil, errors.New("mcpserver: the HTTP transport requires a bearer token verifier")
	}
	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s.mcp }, nil)
	middleware := auth.RequireBearerToken(s.tokenVerifier(), nil)
	mux := http.NewServeMux()
	mux.Handle("/mcp", middleware(streamable))
	return mux, nil
}

// tokenVerifier adapts the injected BearerVerifier to the SDK's
// TokenVerifier type. Every rejection collapses to the SDK's
// ErrInvalidToken (uniform 401, no oracle between unknown and expired);
// the distinction is logged internally.
func (s *Server) tokenVerifier() auth.TokenVerifier {
	return func(ctx context.Context, token string, req *http.Request) (*auth.TokenInfo, error) {
		info, err := s.opts.Verifier.VerifyToken(token)
		if err != nil {
			reason := "invalid"
			if errors.Is(err, identity.ErrExpiredToken) {
				reason = "expired"
			}
			s.logger.Warn("mcpserver: bearer token rejected",
				"reason", reason, "remote_addr", req.RemoteAddr)
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{
			UserID:     info.AgentID,
			Expiration: info.ExpiresAt,
			Extra: map[string]any{
				extraFingerprint: info.Fingerprint,
				// The peer address is observed at the HTTP boundary, not
				// sent by the agent, so it is trustworthy for the decision
				// record (sections 9.1, 12.4). It rides TokenInfo.Extra to
				// the tool handler alongside the fingerprint.
				extraRemoteAddr: req.RemoteAddr,
			},
		}, nil
	}
}

// extraFingerprint keys the token fingerprint inside
// auth.TokenInfo.Extra so request handlers can hand it to the broker
// for the decision record.
const extraFingerprint = "taskgrant_token_fingerprint"

// extraRemoteAddr keys the broker-observed HTTP peer address inside
// auth.TokenInfo.Extra (sections 9.1, 12.4).
const extraRemoteAddr = "taskgrant_remote_addr"

// identify resolves the verified agent identity of one tool call:
// the fixed stdio identity when set, otherwise the bearer identity the
// SDK carried in from the middleware. Returns transport, fingerprint,
// and the broker-observed remote address alongside for the decision
// record. The remote address is empty on stdio (no remote peer).
func (s *Server) identify(req *mcp.CallToolRequest) (agentID, transport, fingerprint, remoteAddr string, err error) {
	if s.opts.FixedAgentID != "" {
		return s.opts.FixedAgentID, TransportStdio, "", "", nil
	}
	if req != nil && req.Extra != nil && req.Extra.TokenInfo != nil {
		id := req.Extra.TokenInfo.UserID
		if verr := domain.ValidateAgentID(id); verr != nil {
			return "", "", "", "", fmt.Errorf("mcpserver: token bound to invalid agent id: %w", verr)
		}
		fp := ""
		if v, ok := req.Extra.TokenInfo.Extra[extraFingerprint].(string); ok {
			fp = v
		}
		addr := ""
		if v, ok := req.Extra.TokenInfo.Extra[extraRemoteAddr].(string); ok {
			addr = v
		}
		return id, TransportHTTP, fp, addr, nil
	}
	return "", "", "", "", errors.New("mcpserver: no agent identity bound to request")
}
