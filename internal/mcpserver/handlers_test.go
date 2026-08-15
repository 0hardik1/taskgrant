package mcpserver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0hardik1/taskgrant/internal/domain"
)

// fakeBroker is a scriptable Broker for tool-layer tests. It records
// the last call's arguments.
type fakeBroker struct {
	view    *GrantView
	explain *GrantExplanation
	listing *CapabilityListing
	release *ReleaseView
	err     error

	lastAgent   string
	lastGrantID string
	lastReq     GrantRequest
	lastOutcome string
	lastNote    string
}

func (f *fakeBroker) RequestGrant(_ context.Context, agentID string, req GrantRequest) (*GrantView, error) {
	f.lastAgent, f.lastReq = agentID, req
	return f.view, f.err
}

func (f *fakeBroker) GetGrant(_ context.Context, agentID, grantID string) (*GrantView, error) {
	f.lastAgent, f.lastGrantID = agentID, grantID
	return f.view, f.err
}

func (f *fakeBroker) ExplainGrant(_ context.Context, agentID, grantID string) (*GrantExplanation, error) {
	f.lastAgent, f.lastGrantID = agentID, grantID
	return f.explain, f.err
}

func (f *fakeBroker) ListCapabilities(_ context.Context, agentID string) (*CapabilityListing, error) {
	f.lastAgent = agentID
	return f.listing, f.err
}

func (f *fakeBroker) ReleaseGrant(_ context.Context, agentID, grantID, outcome, note string) (*ReleaseView, error) {
	f.lastAgent, f.lastGrantID, f.lastOutcome, f.lastNote = agentID, grantID, outcome, note
	return f.release, f.err
}

func newTestServer(t *testing.T, b Broker, opts Options) *Server {
	t.Helper()
	if opts.FixedAgentID == "" {
		opts.FixedAgentID = "test-agent"
	}
	s, err := New(b, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func activeView(grantID string) *GrantView {
	return &GrantView{
		GrantID: grantID,
		Status:  "active",
		Credentials: &Credentials{
			AccessKeyID:     "ASIAEXAMPLE",
			SecretAccessKey: "secret-value",
			SessionToken:    "token-value",
			Expiration:      time.Now().Add(15 * time.Minute),
		},
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
}

func TestRequestGrantBoundaryCaps(t *testing.T) {
	grantID := domain.NewGrantID()
	tests := []struct {
		name      string
		in        RequestGrantInput
		wantField string
	}{
		{"task required", RequestGrantInput{}, "task"},
		{"task 4096 ok", RequestGrantInput{Task: strings.Repeat("a", 4096)}, ""},
		{"task 4097 rejected", RequestGrantInput{Task: strings.Repeat("a", 4097)}, "task"},
		{"reason 1024 ok", RequestGrantInput{Task: "t", Reason: strings.Repeat("r", 1024)}, ""},
		{"reason 1025 rejected", RequestGrantInput{Task: "t", Reason: strings.Repeat("r", 1025)}, "reason"},
		{"negative duration", RequestGrantInput{Task: "t", DurationSeconds: -1}, "duration_seconds"},
		{"too many services", RequestGrantInput{Task: "t", Services: make([]string, MaxServices+1)}, "services"},
		{"capability id required", RequestGrantInput{Task: "t", Capabilities: []CapabilityHintInput{{}}}, "capabilities[0].id"},
		{"oversize retry token", RequestGrantInput{Task: "t", RetryToken: strings.Repeat("x", MaxRetryTokenChars+1)}, "retry_token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := &fakeBroker{view: &GrantView{GrantID: grantID, Status: "denied", DenialCode: domain.DenyNoMatch}}
			s := newTestServer(t, fb, Options{})
			_, out, err := s.handleRequestGrant(context.Background(), &mcp.CallToolRequest{}, tt.in)
			if err != nil {
				t.Fatalf("handler error: %v", err)
			}
			if tt.wantField == "" {
				if out.ErrorCode == CodeInvalidArgument {
					t.Fatalf("unexpected INVALID_ARGUMENT: %s", out.Detail)
				}
				return
			}
			if out.Status != "error" || out.ErrorCode != CodeInvalidArgument {
				t.Fatalf("status=%q code=%q, want error/INVALID_ARGUMENT", out.Status, out.ErrorCode)
			}
			if !strings.HasPrefix(out.Detail, tt.wantField+":") {
				t.Errorf("detail %q does not name field %q", out.Detail, tt.wantField)
			}
		})
	}
}

func TestRequestGrantCallerRefSanitizedAndWaitClamped(t *testing.T) {
	fb := &fakeBroker{view: &GrantView{GrantID: domain.NewGrantID(), Status: "denied", DenialCode: domain.DenyNoMatch}}
	s := newTestServer(t, fb, Options{MaxWaitSeconds: 30})
	in := RequestGrantInput{
		Task:        "archive the invoices",
		CallerRef:   "run-1\x1b[2J;$(rm -rf /)" + strings.Repeat("A", 100),
		WaitSeconds: 300,
	}
	_, out, err := s.handleRequestGrant(context.Background(), &mcp.CallToolRequest{}, in)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if out.ErrorCode == CodeInvalidArgument {
		t.Fatalf("unexpected rejection: %s", out.Detail)
	}
	if got := fb.lastReq.WaitSeconds; got != 30 {
		t.Errorf("WaitSeconds = %d, want clamp to 30", got)
	}
	ref := fb.lastReq.CallerRef
	if len(ref) > domain.CallerRefMaxLen {
		t.Errorf("caller_ref length %d exceeds %d", len(ref), domain.CallerRefMaxLen)
	}
	for _, bad := range []string{"\x1b", "$", "(", ")", ";"} {
		if strings.Contains(ref, bad) {
			t.Errorf("caller_ref %q contains %q after sanitization", ref, bad)
		}
	}
}

func TestCredentialOnceDelivery(t *testing.T) {
	grantID := domain.NewGrantID()
	fb := &fakeBroker{view: activeView(grantID)}
	s := newTestServer(t, fb, Options{})
	ctx := context.Background()
	req := &mcp.CallToolRequest{}

	// First delivery: request_grant carries the secret.
	_, out1, err := s.handleRequestGrant(ctx, req, RequestGrantInput{Task: "t"})
	if err != nil {
		t.Fatalf("request_grant: %v", err)
	}
	if out1.Credentials == nil || out1.Credentials.SecretAccessKey == "" {
		t.Fatal("first response must carry credentials")
	}

	// The broker keeps offering the secret; the tool layer must not
	// repeat it. Both get_grant polls come back without secrets.
	for i := 0; i < 2; i++ {
		_, out, err := s.handleGetGrant(ctx, req, GetGrantInput{GrantID: grantID})
		if err != nil {
			t.Fatalf("get_grant %d: %v", i, err)
		}
		if out.Credentials != nil {
			t.Fatalf("get_grant %d leaked credentials without redelivery", i)
		}
		if out.Status != "active" {
			t.Errorf("get_grant %d status = %q", i, out.Status)
		}
	}

	// A second request_grant replay must not repeat the secret either.
	_, out2, err := s.handleRequestGrant(ctx, req, RequestGrantInput{Task: "t"})
	if err != nil {
		t.Fatalf("request_grant replay: %v", err)
	}
	if out2.Credentials != nil {
		t.Fatal("replayed request_grant repeated the secret")
	}
}

func TestCredentialDeliveryViaGetGrantWhenNeverDelivered(t *testing.T) {
	// Return-and-poll flow: request_grant returned pending_approval
	// with no secret; the first get_grant after mint is the one and
	// only delivery.
	grantID := domain.NewGrantID()
	fb := &fakeBroker{view: activeView(grantID)}
	s := newTestServer(t, fb, Options{})
	ctx := context.Background()
	req := &mcp.CallToolRequest{}

	_, out1, err := s.handleGetGrant(ctx, req, GetGrantInput{GrantID: grantID})
	if err != nil {
		t.Fatalf("get_grant: %v", err)
	}
	if out1.Credentials == nil {
		t.Fatal("first get_grant delivery missing credentials")
	}
	_, out2, err := s.handleGetGrant(ctx, req, GetGrantInput{GrantID: grantID})
	if err != nil {
		t.Fatalf("second get_grant: %v", err)
	}
	if out2.Credentials != nil {
		t.Fatal("second get_grant has a secret; once-delivery broken")
	}
}

func TestCredentialRedeliveryOptIn(t *testing.T) {
	grantID := domain.NewGrantID()
	fb := &fakeBroker{view: activeView(grantID)}
	s := newTestServer(t, fb, Options{CredentialRedelivery: true})
	ctx := context.Background()
	req := &mcp.CallToolRequest{}
	for i := 0; i < 2; i++ {
		_, out, err := s.handleGetGrant(ctx, req, GetGrantInput{GrantID: grantID})
		if err != nil {
			t.Fatalf("get_grant %d: %v", i, err)
		}
		if out.Credentials == nil {
			t.Fatalf("get_grant %d: redelivery enabled but no credentials", i)
		}
	}
}

func TestCrossAgentLookupIsNotFoundNeverForbidden(t *testing.T) {
	grantID := domain.NewGrantID()
	for _, sentinel := range []error{ErrNotFound, ErrForbidden} {
		fb := &fakeBroker{err: sentinel}
		s := newTestServer(t, fb, Options{})
		ctx := context.Background()
		req := &mcp.CallToolRequest{}

		_, out, err := s.handleGetGrant(ctx, req, GetGrantInput{GrantID: grantID})
		if err != nil {
			t.Fatalf("get_grant: %v", err)
		}
		if out.ErrorCode != CodeNotFound {
			t.Errorf("sentinel %v: get_grant code = %q, want NOT_FOUND", sentinel, out.ErrorCode)
		}
		if strings.Contains(strings.ToUpper(out.ErrorCode+out.Detail), "FORBIDDEN") {
			t.Errorf("sentinel %v: response mentions FORBIDDEN", sentinel)
		}

		_, exOut, err := s.handleExplainGrant(ctx, req, ExplainGrantInput{GrantID: grantID})
		if err != nil {
			t.Fatalf("explain_grant: %v", err)
		}
		if exOut.ErrorCode != CodeNotFound {
			t.Errorf("sentinel %v: explain_grant code = %q, want NOT_FOUND", sentinel, exOut.ErrorCode)
		}
	}
}

func TestInternalErrorsAreOpaque(t *testing.T) {
	fb := &fakeBroker{err: errors.New("sts: AccessDenied for arn:aws:iam::111122223333:role/secret-role")}
	s := newTestServer(t, fb, Options{})
	_, out, err := s.handleGetGrant(context.Background(), &mcp.CallToolRequest{}, GetGrantInput{GrantID: domain.NewGrantID()})
	if err != nil {
		t.Fatalf("get_grant: %v", err)
	}
	if out.ErrorCode != CodeInternal {
		t.Fatalf("code = %q, want INTERNAL", out.ErrorCode)
	}
	if strings.Contains(out.Detail, "arn:") || strings.Contains(out.Detail, "AccessDenied") {
		t.Errorf("raw broker error leaked: %q", out.Detail)
	}
}

func TestExplainGrantStripsControlSequences(t *testing.T) {
	grantID := domain.NewGrantID()
	fb := &fakeBroker{explain: &GrantExplanation{
		GrantID:      grantID,
		Status:       "denied",
		Task:         "read docs\x1b[2J\x1b]0;pwned\x07 please",
		Reason:       "ok\x1b[31mred\x1b[0m",
		Outcome:      "denied",
		ApproverRole: "human",
	}}
	s := newTestServer(t, fb, Options{})
	_, out, err := s.handleExplainGrant(context.Background(), &mcp.CallToolRequest{}, ExplainGrantInput{GrantID: grantID})
	if err != nil {
		t.Fatalf("explain_grant: %v", err)
	}
	if strings.ContainsRune(out.Task, 0x1b) || strings.ContainsRune(out.Reason, 0x1b) {
		t.Errorf("escape bytes survived: task=%q reason=%q", out.Task, out.Reason)
	}
	if out.Task != "read docs please" {
		t.Errorf("task = %q, want %q", out.Task, "read docs please")
	}
	if out.Approver != "human" {
		t.Errorf("approver = %q, want role \"human\"", out.Approver)
	}
}

func TestGetGrantPollRateLimit(t *testing.T) {
	grantID := domain.NewGrantID()
	fb := &fakeBroker{view: &GrantView{GrantID: grantID, Status: "pending_approval"}}
	s := newTestServer(t, fb, Options{PollPerMinute: 1, PollBurst: 2})
	ctx := context.Background()
	req := &mcp.CallToolRequest{}

	for i := 0; i < 2; i++ {
		_, out, err := s.handleGetGrant(ctx, req, GetGrantInput{GrantID: grantID})
		if err != nil {
			t.Fatalf("get_grant %d: %v", i, err)
		}
		if out.ErrorCode == CodeRateLimited {
			t.Fatalf("poll %d limited too early", i)
		}
	}
	_, out, err := s.handleGetGrant(ctx, req, GetGrantInput{GrantID: grantID})
	if err != nil {
		t.Fatalf("get_grant: %v", err)
	}
	if out.ErrorCode != CodeRateLimited {
		t.Fatalf("third poll code = %q, want RATE_LIMITED", out.ErrorCode)
	}
}

func TestReleaseGrantValidation(t *testing.T) {
	grantID := domain.NewGrantID()
	fb := &fakeBroker{release: &ReleaseView{GrantID: grantID, Outcome: ReleaseSucceeded, ReleasedAt: time.Now()}}
	s := newTestServer(t, fb, Options{})
	ctx := context.Background()
	req := &mcp.CallToolRequest{}

	_, out, err := s.handleReleaseGrant(ctx, req, ReleaseGrantInput{GrantID: grantID, Outcome: "exploded"})
	if err != nil {
		t.Fatalf("release_grant: %v", err)
	}
	if out.ErrorCode != CodeInvalidArgument {
		t.Errorf("bad outcome accepted: %+v", out)
	}

	_, out, err = s.handleReleaseGrant(ctx, req, ReleaseGrantInput{GrantID: grantID, Outcome: ReleaseSucceeded, Note: strings.Repeat("n", MaxNoteChars+1)})
	if err != nil {
		t.Fatalf("release_grant: %v", err)
	}
	if out.ErrorCode != CodeInvalidArgument {
		t.Errorf("oversize note accepted: %+v", out)
	}

	_, out, err = s.handleReleaseGrant(ctx, req, ReleaseGrantInput{GrantID: grantID, Outcome: ReleaseSucceeded, Note: "done"})
	if err != nil {
		t.Fatalf("release_grant: %v", err)
	}
	if out.Status != "released" || out.Outcome != ReleaseSucceeded {
		t.Errorf("release output = %+v", out)
	}
	if fb.lastNote != "done" {
		t.Errorf("note not passed through: %q", fb.lastNote)
	}
}

func TestStdioRefusesWithoutFixedAgent(t *testing.T) {
	s, err := New(&fakeBroker{}, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.ServeStdio(context.Background()); err == nil {
		t.Fatal("ServeStdio without a fixed agent must refuse to start")
	}
}

func TestInternalCredentialsRedactThemselves(t *testing.T) {
	c := Credentials{AccessKeyID: "AKID", SecretAccessKey: "supersecret", SessionToken: "tok"}
	if s := c.String(); strings.Contains(s, "supersecret") || strings.Contains(s, "tok") {
		t.Errorf("String leaked secrets: %s", s)
	}
	j, err := c.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if strings.Contains(string(j), "supersecret") || strings.Contains(string(j), `"tok"`) {
		t.Errorf("MarshalJSON leaked secrets: %s", j)
	}
}
