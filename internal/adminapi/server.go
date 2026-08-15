package adminapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0hardik1/taskgrant/internal/textsafe"
)

// Request body and note caps; admin callers are trusted humans, but
// the API still bounds every input.
const (
	maxBodyBytes    = 1 << 20 // 1 MiB
	maxNoteChars    = 1024
	defaultLimit    = 100
	maxLimit        = 1000
	maxQueryChars   = 512
	shutdownTimeout = 5 * time.Second
)

// Deps are the injected collaborators. Approvals and Audit are
// required; the rest are optional and their endpoints answer 501 when
// absent.
type Deps struct {
	Approvals ApprovalsBroker
	Audit     AuditStore
	Revoker   Revoker
	Reloader  ConfigReloader
	Ready     ReadyChecker
	Creds     CredsBroker
	Metrics   *Metrics
	Logger    *slog.Logger
}

// Options tunes the admin server.
type Options struct {
	// Bearer authenticates the HTTP binding. ServeTCP refuses to start
	// without it; the unix socket never uses it.
	Bearer AdminTokenVerifier
	// MultiAgentHTTP marks the shared deployment shape (HTTP transport
	// with more than one agent). When true and Bearer is nil, New logs
	// the section 11 startup warning: the only approval path is the
	// pod-local socket, which pod-exec makes meaningless.
	MultiAgentHTTP bool
}

// Server is the admin API: one mux, two listeners.
type Server struct {
	deps    Deps
	opts    Options
	logger  *slog.Logger
	mux     *http.ServeMux
	started time.Time
}

// New builds the admin server and emits startup warnings.
func New(deps Deps, opts Options) (*Server, error) {
	if deps.Approvals == nil {
		return nil, errors.New("adminapi: nil ApprovalsBroker")
	}
	if deps.Audit == nil {
		return nil, errors.New("adminapi: nil AuditStore")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Metrics == nil {
		deps.Metrics = NewMetrics()
	}
	s := &Server{
		deps:    deps,
		opts:    opts,
		logger:  deps.Logger,
		started: time.Now(),
	}
	s.mux = s.routes()

	if opts.MultiAgentHTTP && opts.Bearer == nil {
		s.logger.Warn("adminapi: multi-agent HTTP deployment with only the pod-local unix socket approval path; " +
			"pod-exec makes the OS peer identity meaningless, configure the bearer-authed admin HTTP binding")
	}
	return s, nil
}

// Metrics returns the registry so other packages can record into it.
func (s *Server) Metrics() *Metrics { return s.deps.Metrics }

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/approvals", s.handleApprovalsList)
	mux.HandleFunc("GET /v1/approvals/{id}", s.handleApprovalShow)
	mux.HandleFunc("POST /v1/approvals/{id}/approve", s.handleApprove)
	mux.HandleFunc("POST /v1/approvals/{id}/deny", s.handleDeny)
	mux.HandleFunc("GET /v1/audit/records", s.handleAuditList)
	mux.HandleFunc("GET /v1/audit/grants/{grant_id}", s.handleAuditShow)
	mux.HandleFunc("GET /v1/audit/search", s.handleAuditSearch)
	mux.HandleFunc("GET /v1/audit/scope/{agent}", s.handleAuditScope)
	mux.HandleFunc("POST /v1/audit/verify", s.handleAuditVerify)
	mux.HandleFunc("POST /v1/revoke", s.handleRevoke)
	mux.HandleFunc("POST /v1/creds", s.handleCreds)
	mux.HandleFunc("POST /v1/config/reload", s.handleConfigReload)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	return mux
}

// SocketHandler is the handler the unix socket listener serves:
// the shared mux, with approver identity from peer credentials.
func (s *Server) SocketHandler() http.Handler { return s.mux }

// TCPHandler is the handler the HTTP listener serves: the shared mux
// behind bearer auth. Health and metrics stay open for probes and
// scrapes; everything else requires a verified token.
func (s *Server) TCPHandler() (http.Handler, error) {
	if s.opts.Bearer == nil {
		return nil, errors.New("adminapi: the HTTP binding requires an admin token verifier")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/readyz", "/metrics":
			s.mux.ServeHTTP(w, r)
			return
		}
		principal, ok := s.verifyBearer(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			s.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "a valid admin bearer token is required")
			return
		}
		ctx := context.WithValue(r.Context(), bearerPrincipalKey{}, principal)
		s.mux.ServeHTTP(w, r.WithContext(ctx))
	}), nil
}

type bearerPrincipalKey struct{}

func (s *Server) verifyBearer(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "bearer") {
		return "", false
	}
	principal, err := s.opts.Bearer.VerifyAdminToken(fields[1])
	if err != nil {
		s.logger.Warn("adminapi: admin token rejected", "remote_addr", r.RemoteAddr)
		return "", false
	}
	return principal, true
}

// ServeUnix listens on the admin unix socket until ctx is done. A
// stale socket file from a previous run is removed; the fresh socket
// is restricted to owner and group.
func (s *Server) ServeUnix(ctx context.Context, socketPath string) error {
	if info, err := os.Stat(socketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("adminapi: remove stale socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("adminapi: listen unix %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		ln.Close()
		return fmt.Errorf("adminapi: chmod socket: %w", err)
	}
	srv := &http.Server{
		Handler:           s.SocketHandler(),
		ConnContext:       unixConnContext,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.logger.Info("adminapi: serving unix socket", "path", socketPath)
	return serveUntilDone(ctx, srv, ln)
}

// ServeTCP listens on the bearer-authed HTTP binding until ctx is
// done. TLS termination belongs to a reverse proxy (section 15).
func (s *Server) ServeTCP(ctx context.Context, addr string) error {
	handler, err := s.TCPHandler()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("adminapi: listen tcp %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.logger.Info("adminapi: serving http", "addr", ln.Addr().String())
	return serveUntilDone(ctx, srv, ln)
}

func serveUntilDone(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		<-errCh
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// approverFrom resolves the approver identity of a mutating request:
// the bearer principal on the HTTP binding, the socket peer on the
// unix socket. No identity means no approval authority.
func (s *Server) approverFrom(r *http.Request) (Approver, bool) {
	if principal, ok := r.Context().Value(bearerPrincipalKey{}).(string); ok && principal != "" {
		return Approver{Method: MethodAPI, Principal: principal, UID: -1}, true
	}
	if cred, ok := peerCredFromContext(r.Context()); ok {
		return Approver{
			Method:    MethodCLI,
			Principal: cred.Principal(),
			UID:       cred.UID,
			PID:       cred.PID,
		}, true
	}
	return Approver{}, false
}

// --- approvals ---

func (s *Server) handleApprovalsList(w http.ResponseWriter, r *http.Request) {
	pending, err := s.deps.Approvals.ListPending(r.Context())
	if err != nil {
		s.internalError(w, "approvals list", err)
		return
	}
	if pending == nil {
		pending = []PendingApproval{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"pending": pending,
		// Section 11: approvers see the task text visibly framed as
		// untrusted agent input.
		"agent_input_notice": "task and reason are unverified agent input",
	})
}

func (s *Server) handleApprovalShow(w http.ResponseWriter, r *http.Request) {
	p, err := s.deps.Approvals.GetPending(r.Context(), r.PathValue("id"))
	if err != nil {
		s.approvalError(w, "approval show", err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"approval":           p,
		"agent_input_notice": "task and reason are unverified agent input",
	})
}

type decisionRequest struct {
	Note string `json:"note"`
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	s.handleDecision(w, r, s.deps.Approvals.Approve)
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	s.handleDecision(w, r, s.deps.Approvals.Deny)
}

func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request,
	decide func(context.Context, string, Approver, string) (*ApprovalDecision, error)) {
	approver, ok := s.approverFrom(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "NO_APPROVER_IDENTITY",
			"no verified approver identity on this connection")
		return
	}
	var body decisionRequest
	if !s.decodeBody(w, r, &body) {
		return
	}
	if utf8.RuneCountInString(body.Note) > maxNoteChars {
		s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT",
			fmt.Sprintf("note: longer than %d characters", maxNoteChars))
		return
	}
	decision, err := decide(r.Context(), r.PathValue("id"), approver, body.Note)
	if err != nil {
		s.approvalError(w, "approval decision", err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision,
		"approver": approver,
	})
}

func (s *Server) approvalError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		s.writeError(w, http.StatusNotFound, "NOT_FOUND", "no such approval")
	case errors.Is(err, ErrAlreadyDecided):
		s.writeError(w, http.StatusConflict, "ALREADY_DECIDED", "the approval was already decided")
	case errors.Is(err, ErrExpired):
		s.writeError(w, http.StatusGone, "EXPIRED", "the pending approval passed its TTL")
	default:
		s.internalError(w, op, err)
	}
}

// --- audit ---

func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	q := AuditQuery{
		Agent:    r.URL.Query().Get("agent"),
		Profile:  r.URL.Query().Get("profile"),
		Outcome:  r.URL.Query().Get("outcome"),
		Resource: r.URL.Query().Get("resource"),
		Limit:    defaultLimit,
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := parseLimit(v)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "limit: "+err.Error())
			return
		}
		q.Limit = n
	}
	for name, dst := range map[string]*time.Time{"since": &q.Since, "until": &q.Until} {
		if v := r.URL.Query().Get(name); v != "" {
			t, err := parseTimeParam(v)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", name+": "+err.Error())
				return
			}
			*dst = t
		}
	}
	records, err := s.deps.Audit.ListRecords(r.Context(), q)
	if err != nil {
		s.internalError(w, "audit list", err)
		return
	}
	if records == nil {
		records = []AuditRecord{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

func (s *Server) handleAuditShow(w http.ResponseWriter, r *http.Request) {
	records, err := s.deps.Audit.GrantRecords(r.Context(), r.PathValue("grant_id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "NOT_FOUND", "no such grant")
			return
		}
		s.internalError(w, "audit show", err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

func (s *Server) handleAuditSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "q: required")
		return
	}
	if utf8.RuneCountInString(query) > maxQueryChars {
		s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT",
			fmt.Sprintf("q: longer than %d characters", maxQueryChars))
		return
	}
	limit := defaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := parseLimit(v)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "limit: "+err.Error())
			return
		}
		limit = n
	}
	records, err := s.deps.Audit.Search(r.Context(), query, limit)
	if err != nil {
		s.internalError(w, "audit search", err)
		return
	}
	if records == nil {
		records = []AuditRecord{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

func (s *Server) handleAuditScope(w http.ResponseWriter, r *http.Request) {
	report, err := s.deps.Audit.Scope(r.Context(), r.PathValue("agent"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "NOT_FOUND", "no such agent")
			return
		}
		s.internalError(w, "audit scope", err)
		return
	}
	s.writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	result, err := s.deps.Audit.Verify(r.Context())
	if err != nil {
		s.internalError(w, "audit verify", err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

// --- revoke and reload ---

type revokeRequest struct {
	Profile string `json:"profile"`
	GrantID string `json:"grant_id"`
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if s.deps.Revoker == nil {
		s.writeError(w, http.StatusNotImplemented, "REVOCATION_DISABLED",
			"revocation is disabled in config (revocation.enabled)")
		return
	}
	var body revokeRequest
	if !s.decodeBody(w, r, &body) {
		return
	}
	var (
		result *RevocationResult
		err    error
	)
	switch {
	case body.Profile != "" && body.GrantID == "":
		result, err = s.deps.Revoker.RevokeProfile(r.Context(), body.Profile)
	case body.GrantID != "" && body.Profile == "":
		result, err = s.deps.Revoker.RevokeGrant(r.Context(), body.GrantID)
	default:
		s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT",
			"exactly one of profile or grant_id is required")
		return
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "NOT_FOUND", "no such profile or grant")
			return
		}
		s.internalError(w, "revoke", err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

// handleCreds serves the `taskgrant creds` helper (section 4.3): a
// grant request over the local admin socket, answered in one shot with
// either credentials or the structured non-active outcome.
func (s *Server) handleCreds(w http.ResponseWriter, r *http.Request) {
	if s.deps.Creds == nil {
		s.writeError(w, http.StatusNotImplemented, "CREDS_UNAVAILABLE",
			"the creds helper is not wired on this server")
		return
	}
	var body CredsRequest
	if !s.decodeBody(w, r, &body) {
		return
	}
	resp, err := s.deps.Creds.RequestCredentials(r.Context(), body)
	if err != nil {
		s.internalError(w, "creds", err)
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if s.deps.Reloader == nil {
		s.writeError(w, http.StatusNotImplemented, "RELOAD_UNAVAILABLE",
			"config reload is not wired on this server")
		return
	}
	if err := s.deps.Reloader.Reload(r.Context()); err != nil {
		// Reload failures carry validation detail meant for the admin.
		s.writeError(w, http.StatusUnprocessableEntity, "RELOAD_FAILED", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "reloaded"})
}

// --- health and metrics ---

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"uptime_seconds": int(time.Since(s.started).Seconds()),
	})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.deps.Ready != nil {
		if err := s.deps.Ready.Ready(r.Context()); err != nil {
			s.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "unready",
				"detail": err.Error(),
			})
			return
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := s.deps.Metrics.WritePrometheus(w); err != nil {
		s.logger.Error("adminapi: metrics render", "err", err)
	}
}

// --- plumbing ---

// decodeBody reads a capped JSON body into v. An empty body decodes to
// the zero value.
func (s *Server) decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "unreadable request body")
		return false
	}
	if len(data) == 0 {
		return true
	}
	if err := json.Unmarshal(data, v); err != nil {
		s.writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "request body is not valid JSON")
		return false
	}
	return true
}

// writeJSON renders v with every string in the payload sanitized
// (section 12.5): the payload embeds hostile agent bytes, and this is
// the human-facing boundary.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		s.logger.Error("adminapi: response encoding", "err", err)
		http.Error(w, `{"error":"ENCODING"}`, http.StatusInternalServerError)
		return
	}
	clean, err := textsafe.SanitizeJSON(data)
	if err != nil {
		s.logger.Error("adminapi: response sanitization", "err", err)
		http.Error(w, `{"error":"ENCODING"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(clean); err != nil {
		s.logger.Debug("adminapi: response write", "err", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, detail string) {
	s.writeJSON(w, status, map[string]any{"error": code, "detail": detail})
}

// internalError logs the full error and answers with an opaque 500.
func (s *Server) internalError(w http.ResponseWriter, op string, err error) {
	s.logger.Error("adminapi: "+op, "err", err)
	s.writeError(w, http.StatusInternalServerError, "INTERNAL", "internal error; the incident is logged")
}

func parseLimit(v string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 1 {
		return 0, errors.New("must be a positive integer")
	}
	if n > maxLimit {
		n = maxLimit
	}
	return n, nil
}

func parseTimeParam(v string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("must be RFC 3339 or YYYY-MM-DD")
}

// StaticTokenVerifier is a minimal AdminTokenVerifier: one principal,
// one SHA-256 token hash from config, constant-time comparison. Real
// deployments can inject richer verifiers.
type StaticTokenVerifier struct {
	PrincipalName string
	SHA256Hex     string
}

// VerifyAdminToken implements AdminTokenVerifier.
func (v StaticTokenVerifier) VerifyAdminToken(token string) (string, error) {
	want, err := hex.DecodeString(v.SHA256Hex)
	if err != nil || len(want) != sha256.Size {
		return "", errors.New("adminapi: misconfigured admin token hash")
	}
	sum := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return "", errors.New("adminapi: unknown admin token")
	}
	return v.PrincipalName, nil
}
