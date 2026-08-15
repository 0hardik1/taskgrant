package adminapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// socketClient returns an http.Client that dials the unix socket.
func socketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
}

// shortSocketPath returns a socket path short enough for the sun_path
// limit (104 bytes on darwin); t.TempDir can run long.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tg")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "admin.sock")
	if len(path) > 100 {
		t.Skipf("temp socket path too long: %s", path)
	}
	return path
}

func startUnixServer(t *testing.T, deps Deps) (string, *fakeApprovals) {
	t.Helper()
	fa := deps.Approvals.(*fakeApprovals)
	s, err := New(deps, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	socketPath := shortSocketPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.ServeUnix(ctx, socketPath)
	}()
	t.Cleanup(func() { cancel(); <-done })

	// Wait for the socket to accept connections.
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket never came up: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return socketPath, fa
}

func TestUnixSocketApproveRoundTrip(t *testing.T) {
	deps, _, _ := newTestDeps()
	socketPath, fa := startUnixServer(t, deps)
	client := socketClient(socketPath)

	// List pending approvals over the socket.
	fa.pending = []PendingApproval{{ID: "ap-9", GrantID: "g-9", AgentID: "invoice-bot", Task: "archive things"}}
	resp, err := client.Get("http://taskgrant/v1/approvals")
	if err != nil {
		t.Fatalf("GET approvals: %v", err)
	}
	var listing struct {
		Pending []PendingApproval `json:"pending"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	resp.Body.Close()
	if len(listing.Pending) != 1 || listing.Pending[0].ID != "ap-9" {
		t.Fatalf("listing = %+v", listing)
	}

	// Approve it; the OS peer credential is the approver identity.
	resp, err = client.Post("http://taskgrant/v1/approvals/ap-9/approve",
		"application/json", strings.NewReader(`{"note":"looks right"}`))
	if err != nil {
		t.Fatalf("POST approve: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d", resp.StatusCode)
	}
	var decided struct {
		Decision ApprovalDecision `json:"decision"`
		Approver Approver         `json:"approver"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decided); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if decided.Decision.Decision != "approved" || decided.Decision.ID != "ap-9" {
		t.Errorf("decision = %+v", decided.Decision)
	}

	// The broker saw the socket peer as the approver: this process.
	if fa.lastAction != "approve" || fa.lastID != "ap-9" {
		t.Errorf("broker saw action=%q id=%q", fa.lastAction, fa.lastID)
	}
	if fa.lastApprover.Method != MethodCLI {
		t.Errorf("approver method = %q, want %q", fa.lastApprover.Method, MethodCLI)
	}
	if fa.lastApprover.UID != os.Getuid() {
		t.Errorf("approver uid = %d, want %d", fa.lastApprover.UID, os.Getuid())
	}
	if fa.lastApprover.Principal == "" {
		t.Error("approver principal is empty")
	}
	if fa.lastNote != "looks right" {
		t.Errorf("note = %q", fa.lastNote)
	}
}

func TestUnixSocketDenyRoundTrip(t *testing.T) {
	deps, _, _ := newTestDeps()
	socketPath, fa := startUnixServer(t, deps)
	client := socketClient(socketPath)

	resp, err := client.Post("http://taskgrant/v1/approvals/ap-3/deny",
		"application/json", strings.NewReader(`{"note":"scope too broad"}`))
	if err != nil {
		t.Fatalf("POST deny: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deny status = %d", resp.StatusCode)
	}
	if fa.lastAction != "deny" || fa.lastID != "ap-3" {
		t.Errorf("broker saw action=%q id=%q", fa.lastAction, fa.lastID)
	}
	if fa.lastApprover.Method != MethodCLI || fa.lastApprover.UID != os.Getuid() {
		t.Errorf("approver = %+v", fa.lastApprover)
	}
}

func TestUnixSocketReplacesStaleSocket(t *testing.T) {
	deps, _, _ := newTestDeps()
	socketPath := shortSocketPath(t)

	// Leave a stale socket file behind.
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("pre-listen: %v", err)
	}
	ln.Close() // closing removes it on some platforms; recreate raw
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
			t.Fatalf("plant stale file: %v", err)
		}
		// A plain file is not a socket; ServeUnix must refuse rather
		// than delete arbitrary files.
		s, err := New(deps, Options{})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.ServeUnix(ctx, socketPath); err == nil {
			t.Fatal("ServeUnix over a plain file must fail")
		}
		return
	}

	// Socket file still present: a new server must replace it.
	s, err := New(deps, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeUnix(ctx, socketPath) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("replacement socket never came up: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestStartupWarningMultiAgentSocketOnly(t *testing.T) {
	deps, _, _ := newTestDeps()
	var captured strings.Builder
	deps.Logger = newCapturingLogger(&captured)
	if _, err := New(deps, Options{MultiAgentHTTP: true}); err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.Contains(captured.String(), "pod-local unix socket approval path") {
		t.Errorf("expected startup warning, got logs: %s", captured.String())
	}

	// With a bearer verifier configured, no warning.
	captured.Reset()
	if _, err := New(deps, Options{MultiAgentHTTP: true, Bearer: testVerifier()}); err != nil {
		t.Fatalf("New: %v", err)
	}
	if strings.Contains(captured.String(), "pod-local unix socket approval path") {
		t.Errorf("unexpected warning with bearer configured: %s", captured.String())
	}
}

// newCapturingLogger returns a slog.Logger writing text lines into sb.
func newCapturingLogger(sb *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(sb, nil))
}
