package adminapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeApprovals is a scriptable ApprovalsBroker recording the approver
// identity it was handed.
type fakeApprovals struct {
	pending []PendingApproval
	err     error

	lastID       string
	lastApprover Approver
	lastNote     string
	lastAction   string
}

func (f *fakeApprovals) ListPending(context.Context) ([]PendingApproval, error) {
	return f.pending, f.err
}

func (f *fakeApprovals) GetPending(_ context.Context, id string) (*PendingApproval, error) {
	if f.err != nil {
		return nil, f.err
	}
	for i := range f.pending {
		if f.pending[i].ID == id {
			return &f.pending[i], nil
		}
	}
	return nil, ErrNotFound
}

func (f *fakeApprovals) Approve(_ context.Context, id string, by Approver, note string) (*ApprovalDecision, error) {
	f.lastID, f.lastApprover, f.lastNote, f.lastAction = id, by, note, "approve"
	if f.err != nil {
		return nil, f.err
	}
	return &ApprovalDecision{ID: id, GrantID: "g-" + id, Decision: "approved", DecidedAt: time.Now(), MintOutcome: "minted"}, nil
}

func (f *fakeApprovals) Deny(_ context.Context, id string, by Approver, note string) (*ApprovalDecision, error) {
	f.lastID, f.lastApprover, f.lastNote, f.lastAction = id, by, note, "deny"
	if f.err != nil {
		return nil, f.err
	}
	return &ApprovalDecision{ID: id, GrantID: "g-" + id, Decision: "denied", DecidedAt: time.Now()}, nil
}

// fakeAudit is a scriptable AuditStore.
type fakeAudit struct {
	records []AuditRecord
	scope   *ScopeReport
	verify  *ChainVerification
	err     error
}

func (f *fakeAudit) ListRecords(context.Context, AuditQuery) ([]AuditRecord, error) {
	return f.records, f.err
}
func (f *fakeAudit) GrantRecords(context.Context, string) ([]AuditRecord, error) {
	return f.records, f.err
}
func (f *fakeAudit) Search(context.Context, string, int) ([]AuditRecord, error) {
	return f.records, f.err
}
func (f *fakeAudit) Scope(context.Context, string) (*ScopeReport, error) { return f.scope, f.err }
func (f *fakeAudit) Verify(context.Context) (*ChainVerification, error)  { return f.verify, f.err }

const testAdminToken = "admin-token-for-tests"

func testVerifier() StaticTokenVerifier {
	sum := sha256.Sum256([]byte(testAdminToken))
	return StaticTokenVerifier{PrincipalName: "ops-oncall", SHA256Hex: hex.EncodeToString(sum[:])}
}

func newTestDeps() (Deps, *fakeApprovals, *fakeAudit) {
	fa := &fakeApprovals{}
	fs := &fakeAudit{verify: &ChainVerification{OK: true, RecordsChecked: 1}}
	return Deps{Approvals: fa, Audit: fs}, fa, fs
}

func newTCPServer(t *testing.T, deps Deps) *httptest.Server {
	t.Helper()
	s, err := New(deps, Options{Bearer: testVerifier()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h, err := s.TCPHandler()
	if err != nil {
		t.Fatalf("TCPHandler: %v", err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func doReq(t *testing.T, method, url, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, data
}

func TestTCPBearerAuth(t *testing.T) {
	deps, _, _ := newTestDeps()
	ts := newTCPServer(t, deps)

	tests := []struct {
		name       string
		path       string
		token      string
		wantStatus int
	}{
		{"no token rejected", "/v1/approvals", "", http.StatusUnauthorized},
		{"wrong token rejected", "/v1/approvals", "nope", http.StatusUnauthorized},
		{"valid token accepted", "/v1/approvals", testAdminToken, http.StatusOK},
		{"healthz open", "/healthz", "", http.StatusOK},
		{"readyz open", "/readyz", "", http.StatusOK},
		{"metrics open", "/metrics", "", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := doReq(t, http.MethodGet, ts.URL+tt.path, tt.token, nil)
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", resp.StatusCode, tt.wantStatus, body)
			}
		})
	}
}

func TestTCPApproveCarriesBearerPrincipal(t *testing.T) {
	deps, fa, _ := newTestDeps()
	ts := newTCPServer(t, deps)

	resp, body := doReq(t, http.MethodPost, ts.URL+"/v1/approvals/ap-1/approve", testAdminToken,
		map[string]string{"note": "checked the ticket"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	if fa.lastApprover.Method != MethodAPI {
		t.Errorf("approver method = %q, want %q", fa.lastApprover.Method, MethodAPI)
	}
	if fa.lastApprover.Principal != "ops-oncall" {
		t.Errorf("approver principal = %q, want ops-oncall", fa.lastApprover.Principal)
	}
	if fa.lastNote != "checked the ticket" {
		t.Errorf("note = %q", fa.lastNote)
	}
}

func TestApprovalErrorMapping(t *testing.T) {
	tests := []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{ErrNotFound, http.StatusNotFound, "NOT_FOUND"},
		{ErrAlreadyDecided, http.StatusConflict, "ALREADY_DECIDED"},
		{ErrExpired, http.StatusGone, "EXPIRED"},
		{errors.New("db exploded with secrets"), http.StatusInternalServerError, "INTERNAL"},
	}
	for _, tt := range tests {
		t.Run(tt.wantCode, func(t *testing.T) {
			deps, fa, _ := newTestDeps()
			fa.err = tt.err
			ts := newTCPServer(t, deps)
			resp, body := doReq(t, http.MethodPost, ts.URL+"/v1/approvals/x/approve", testAdminToken, nil)
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			var payload struct {
				Error  string `json:"error"`
				Detail string `json:"detail"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("unmarshal %s: %v", body, err)
			}
			if payload.Error != tt.wantCode {
				t.Errorf("code = %q, want %q", payload.Error, tt.wantCode)
			}
			if strings.Contains(payload.Detail, "secrets") {
				t.Errorf("internal error detail leaked: %q", payload.Detail)
			}
		})
	}
}

func TestResponsesStripControlSequences(t *testing.T) {
	deps, fa, fs := newTestDeps()
	hostile := "read docs\x1b[2J\x1b]0;pwned\x07 now"
	fa.pending = []PendingApproval{{
		ID:      "ap-1",
		GrantID: "01HZZZZZZZZZZZZZZZZZZZZZZZ",
		AgentID: "invoice-bot",
		Task:    hostile,
		Reason:  "because\x1b[31m",
	}}
	fs.records = []AuditRecord{{
		RecordID: "r1",
		GrantID:  "g1",
		Kind:     "grant_decision",
		AgentID:  "invoice-bot",
		Body:     json.RawMessage(`{"task":"evil \u001b[2J wipe","nested":{"reason":"x\u0007y"}}`),
	}}
	ts := newTCPServer(t, deps)

	for _, path := range []string{"/v1/approvals", "/v1/approvals/ap-1", "/v1/audit/records", "/v1/audit/grants/g1"} {
		t.Run(path, func(t *testing.T) {
			resp, body := doReq(t, http.MethodGet, ts.URL+path, testAdminToken, nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body %s", resp.StatusCode, body)
			}
			if bytes.ContainsRune(body, 0x1b) || bytes.ContainsRune(body, 0x07) ||
				bytes.Contains(body, []byte(`\u001b`)) || bytes.Contains(body, []byte(`\u0007`)) {
				t.Errorf("control sequences survived in %s: %s", path, body)
			}
			if !json.Valid(body) {
				t.Errorf("response is not valid JSON: %s", body)
			}
		})
	}
}

func TestRevokeAndReloadDisabled(t *testing.T) {
	deps, _, _ := newTestDeps()
	ts := newTCPServer(t, deps)

	resp, body := doReq(t, http.MethodPost, ts.URL+"/v1/revoke", testAdminToken,
		map[string]string{"profile": "p"})
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("revoke status = %d, body %s", resp.StatusCode, body)
	}
	resp, body = doReq(t, http.MethodPost, ts.URL+"/v1/config/reload", testAdminToken, nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("reload status = %d, body %s", resp.StatusCode, body)
	}
}

func TestRevokeValidation(t *testing.T) {
	deps, _, _ := newTestDeps()
	deps.Revoker = &fakeRevoker{}
	ts := newTCPServer(t, deps)

	// Both selectors set: rejected.
	resp, _ := doReq(t, http.MethodPost, ts.URL+"/v1/revoke", testAdminToken,
		map[string]string{"profile": "p", "grant_id": "g"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("both selectors: status = %d, want 400", resp.StatusCode)
	}
	// Neither set: rejected.
	resp, _ = doReq(t, http.MethodPost, ts.URL+"/v1/revoke", testAdminToken, map[string]string{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no selector: status = %d, want 400", resp.StatusCode)
	}
	// Profile alone: accepted.
	resp, body := doReq(t, http.MethodPost, ts.URL+"/v1/revoke", testAdminToken,
		map[string]string{"profile": "p"})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("profile revoke: status = %d, body %s", resp.StatusCode, body)
	}
}

type fakeRevoker struct{}

func (fakeRevoker) RevokeProfile(_ context.Context, profile string) (*RevocationResult, error) {
	return &RevocationResult{Mechanism: "deny-by-issue-time", Profile: profile, AppliedAt: time.Now()}, nil
}

func (fakeRevoker) RevokeGrant(_ context.Context, grantID string) (*RevocationResult, error) {
	return &RevocationResult{Mechanism: "deny-by-grant-tag", GrantID: grantID, AppliedAt: time.Now()}, nil
}

func TestReadyzUnready(t *testing.T) {
	deps, _, _ := newTestDeps()
	deps.Ready = readyFunc(func(context.Context) error { return errors.New("store not open") })
	ts := newTCPServer(t, deps)
	resp, body := doReq(t, http.MethodGet, ts.URL+"/readyz", "", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, body %s", resp.StatusCode, body)
	}
}

type readyFunc func(context.Context) error

func (f readyFunc) Ready(ctx context.Context) error { return f(ctx) }

func TestTCPHandlerRefusesWithoutBearer(t *testing.T) {
	deps, _, _ := newTestDeps()
	s, err := New(deps, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.TCPHandler(); err == nil {
		t.Fatal("TCPHandler without a verifier must refuse")
	}
}

func TestMetricsEndpointServesRegistry(t *testing.T) {
	deps, _, _ := newTestDeps()
	deps.Metrics = NewMetrics()
	deps.Metrics.IncGrantOutcome("denied")
	ts := newTCPServer(t, deps)
	resp, body := doReq(t, http.MethodGet, ts.URL+"/metrics", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type = %q", ct)
	}
	if !strings.Contains(string(body), `taskgrant_grants_total{outcome="denied"} 1`) {
		t.Errorf("metrics body missing counter:\n%s", body)
	}
}
