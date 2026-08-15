package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0hardik1/taskgrant/internal/config"
	"github.com/0hardik1/taskgrant/internal/identity"
)

// bearerTransport injects one Authorization header on every request.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if b.token != "" {
		clone.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(clone)
}

// identityBroker echoes the authenticated agent id back through
// list_capabilities so tests can observe which identity the session is
// bound to.
type identityBroker struct{ fakeBroker }

func (b *identityBroker) ListCapabilities(_ context.Context, agentID string) (*CapabilityListing, error) {
	return &CapabilityListing{Profiles: []string{"profile-of-" + agentID}}, nil
}

func newHTTPFixture(t *testing.T) (endpoint string, tokens map[string]string) {
	t.Helper()

	tokens = make(map[string]string)
	agents := make(map[string]config.AgentConfig)
	for _, id := range []string{"alpha", "beta"} {
		gen, err := identity.GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		tokens[id] = gen.Plaintext
		agents[id] = config.AgentConfig{
			TokenSHA256:  gen.SHA256Hex,
			TokenExpires: time.Now().Add(time.Hour),
			Profiles:     []string{"p"},
		}
	}
	cfg := &config.Config{Agents: agents}
	reg, err := identity.NewRegistry(cfg)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	s, err := New(&identityBroker{}, Options{Verifier: reg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler, err := s.HTTPHandler()
	if err != nil {
		t.Fatalf("HTTPHandler: %v", err)
	}
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts.URL + "/mcp", tokens
}

func connectClient(ctx context.Context, endpoint, token string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint: endpoint,
		HTTPClient: &http.Client{
			Transport: &bearerTransport{token: token, base: http.DefaultTransport},
		},
	}
	return client.Connect(ctx, transport, nil)
}

func TestHTTPBearerAuthRejectAndAccept(t *testing.T) {
	endpoint, tokens := newHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// No token: the middleware must refuse before any MCP handling.
	if _, err := connectClient(ctx, endpoint, ""); err == nil {
		t.Fatal("connect without token succeeded")
	}
	// Wrong token: same refusal.
	if _, err := connectClient(ctx, endpoint, "tgt_not-a-real-token"); err == nil {
		t.Fatal("connect with a bogus token succeeded")
	}

	// Valid token: the session works and runs as the token's agent.
	session, err := connectClient(ctx, endpoint, tokens["alpha"])
	if err != nil {
		t.Fatalf("connect with valid token: %v", err)
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_capabilities",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	if got := structuredProfiles(t, res); got != "profile-of-alpha" {
		t.Errorf("session ran as %q, want profile-of-alpha", got)
	}
}

func TestHTTPSessionBindsTokenIdentity(t *testing.T) {
	endpoint, tokens := newHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Two concurrent sessions with different tokens must each observe
	// their own identity; TokenInfo.UserID binds the session.
	for agent, token := range tokens {
		session, err := connectClient(ctx, endpoint, token)
		if err != nil {
			t.Fatalf("connect %s: %v", agent, err)
		}
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      "list_capabilities",
			Arguments: map[string]any{},
		})
		if err != nil {
			t.Fatalf("CallTool %s: %v", agent, err)
		}
		if got, want := structuredProfiles(t, res), "profile-of-"+agent; got != want {
			t.Errorf("agent %s observed %q, want %q", agent, got, want)
		}
		session.Close()
	}
}

func TestHTTPExpiredTokenRejected(t *testing.T) {
	gen, err := identity.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	cfg := &config.Config{Agents: map[string]config.AgentConfig{
		"stale": {
			TokenSHA256:  gen.SHA256Hex,
			TokenExpires: time.Now().Add(-time.Minute),
			Profiles:     []string{"p"},
		},
	}}
	reg, err := identity.NewRegistry(cfg)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	s, err := New(&identityBroker{}, Options{Verifier: reg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler, err := s.HTTPHandler()
	if err != nil {
		t.Fatalf("HTTPHandler: %v", err)
	}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := connectClient(ctx, ts.URL+"/mcp", gen.Plaintext); err == nil {
		t.Fatal("connect with an expired token succeeded")
	}
}

// TestHTTPGrantRecordsRemoteAddr is the F5 regression (scenario S099):
// a grant that arrives over HTTP must carry the broker-observed peer
// address into the request the broker records (sections 9.1, 12.4).
// Before the fix, remote_addr was never threaded off the HTTP boundary.
func TestHTTPGrantRecordsRemoteAddr(t *testing.T) {
	gen, err := identity.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	cfg := &config.Config{Agents: map[string]config.AgentConfig{
		"alpha": {
			TokenSHA256:  gen.SHA256Hex,
			TokenExpires: time.Now().Add(time.Hour),
			Profiles:     []string{"p"},
		},
	}}
	reg, err := identity.NewRegistry(cfg)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	fb := &fakeBroker{view: &GrantView{GrantID: "g", Status: "denied"}}
	s, err := New(fb, Options{Verifier: reg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler, err := s.HTTPHandler()
	if err != nil {
		t.Fatalf("HTTPHandler: %v", err)
	}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := connectClient(ctx, ts.URL+"/mcp", gen.Plaintext)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	if _, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "request_grant",
		Arguments: map[string]any{"task": "archive the invoices"},
	}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if fb.lastReq.Transport != TransportHTTP {
		t.Fatalf("transport = %q, want http", fb.lastReq.Transport)
	}
	if fb.lastReq.RemoteAddr == "" {
		t.Fatal("an HTTP-originated grant recorded no remote_addr (sections 9.1, 12.4)")
	}
}

func TestHTTPHandlerRefusesMisconfiguration(t *testing.T) {
	s, err := New(&fakeBroker{}, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.HTTPHandler(); err == nil {
		t.Fatal("HTTPHandler without a verifier must refuse")
	}

	s2, err := New(&fakeBroker{}, Options{FixedAgentID: "solo-agent"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s2.HTTPHandler(); err == nil {
		t.Fatal("HTTPHandler with a fixed agent must refuse")
	}
}

// structuredProfiles extracts profiles[0] from a list_capabilities
// result.
func structuredProfiles(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out ListCapabilitiesOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal structured content %s: %v", raw, err)
	}
	if len(out.Profiles) == 0 {
		t.Fatalf("no profiles in %s", raw)
	}
	return strings.Join(out.Profiles[:1], "")
}
