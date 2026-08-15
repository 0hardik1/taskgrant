package revoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"
)

// ErrNoSuchPolicy marks a read of a role policy that does not exist.
// PolicyWriter implementations must return it for that case.
var ErrNoSuchPolicy = errors.New("revoke: role policy does not exist")

// ErrPolicyTooLarge marks a write that would exceed the IAM inline
// policy ceiling even after garbage collection.
var ErrPolicyTooLarge = errors.New("revoke: revocation policy would exceed the inline policy size ceiling")

// ErrClosed marks an operation on a closed Revoker.
var ErrClosed = errors.New("revoke: revoker is closed")

// PolicyWriter is the consumer-side seam over IAM inline role policy
// calls. Production wires an IAM-backed implementation; tests inject a
// fake. Documents cross this interface as plain JSON.
type PolicyWriter interface {
	PutRolePolicy(ctx context.Context, roleName, policyName, document string) error
	GetRolePolicy(ctx context.Context, roleName, policyName string) (document string, err error)
	DeleteRolePolicy(ctx context.Context, roleName, policyName string) error
}

// Options tunes a Revoker.
type Options struct {
	// PolicyName overrides the inline policy name. Defaults to
	// PolicyName.
	PolicyName string
	// Margin is the propagation margin added to the issue-time cutoff.
	// Defaults to DefaultIssueTimeMargin.
	Margin time.Duration
	// MaxSessionDuration bounds how long a pre-cutoff session can
	// outlive a role-wide revocation. Defaults to 12 h, the STS
	// ceiling.
	MaxSessionDuration time.Duration
	// WarnChars is the accumulated-size warning threshold. Defaults to
	// DefaultWarnChars.
	WarnChars int
	// Clock overrides time.Now for tests.
	Clock func() time.Time
	// Logger receives warnings. Defaults to slog.Default().
	Logger *slog.Logger
}

// Result reports one applied revocation or GC pass.
type Result struct {
	Role        string
	PolicyName  string
	Sid         string   // Sid of the statement written; empty for GC
	Statements  int      // statements in the document after the write
	PolicyChars int      // document size after the write
	Warned      bool     // size crossed the warn threshold
	RemovedSids []string // statements dropped by GC in this pass
	Deleted     bool     // the policy became empty and was deleted
}

// Revoker writes deny statements to base roles. Every mutation flows
// through one worker goroutine, so read-modify-write on the inline
// policy never races (section 8.5).
type Revoker struct {
	writer PolicyWriter
	opts   Options

	requests chan request
	stopped  chan struct{}
	done     chan struct{}
}

type request struct {
	ctx   context.Context
	role  string
	stmt  *Statement // nil for a GC-only pass
	reply chan reply
}

type reply struct {
	res Result
	err error
}

// New validates options and starts the single writer goroutine.
func New(writer PolicyWriter, opts Options) (*Revoker, error) {
	if writer == nil {
		return nil, errors.New("revoke: policy writer is required")
	}
	if opts.PolicyName == "" {
		opts.PolicyName = PolicyName
	}
	if opts.Margin <= 0 {
		opts.Margin = DefaultIssueTimeMargin
	}
	if opts.MaxSessionDuration <= 0 {
		opts.MaxSessionDuration = 12 * time.Hour
	}
	if opts.WarnChars <= 0 {
		opts.WarnChars = DefaultWarnChars
	}
	if opts.WarnChars > MaxInlinePolicyChars {
		return nil, fmt.Errorf("revoke: warn threshold %d exceeds the IAM ceiling %d",
			opts.WarnChars, MaxInlinePolicyChars)
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	r := &Revoker{
		writer:   writer,
		opts:     opts,
		requests: make(chan request),
		stopped:  make(chan struct{}),
		done:     make(chan struct{}),
	}
	go r.run()
	return r, nil
}

// Close stops the worker. In-flight operations finish; later calls
// return ErrClosed.
func (r *Revoker) Close() {
	select {
	case <-r.stopped:
		return
	default:
	}
	close(r.stopped)
	<-r.done
}

// RevokeRole applies the role-wide deny: every session of roleName
// whose token was issued before now plus margin loses access
// ("taskgrant revoke --profile").
func (r *Revoker) RevokeRole(ctx context.Context, roleName string) (Result, error) {
	if roleName == "" {
		return Result{}, errors.New("revoke: role name is required")
	}
	stmt := RoleWideDeny(r.opts.Clock(), r.opts.Margin, r.opts.MaxSessionDuration)
	return r.submit(ctx, roleName, &stmt)
}

// RevokeGrant applies the best-effort per-grant deny, keyed only on the
// broker-authored grant ULID (I3). grantExpiry is the credential expiry
// of the grant; it bounds how long the statement lives before GC.
func (r *Revoker) RevokeGrant(ctx context.Context, roleName, grantID string, grantExpiry time.Time) (Result, error) {
	if roleName == "" {
		return Result{}, errors.New("revoke: role name is required")
	}
	stmt, err := GrantDeny(grantID, r.opts.Clock(), r.opts.Margin, r.opts.MaxSessionDuration, grantExpiry)
	if err != nil {
		return Result{}, err
	}
	return r.submit(ctx, roleName, &stmt)
}

// GC removes expired deny statements from the role's revocation policy
// and deletes the policy when it becomes empty.
func (r *Revoker) GC(ctx context.Context, roleName string) (Result, error) {
	if roleName == "" {
		return Result{}, errors.New("revoke: role name is required")
	}
	return r.submit(ctx, roleName, nil)
}

func (r *Revoker) submit(ctx context.Context, role string, stmt *Statement) (Result, error) {
	req := request{ctx: ctx, role: role, stmt: stmt, reply: make(chan reply, 1)}
	select {
	case <-r.stopped:
		return Result{}, ErrClosed
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case r.requests <- req:
	}
	select {
	case rep := <-req.reply:
		return rep.res, rep.err
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

// run is the single writer goroutine.
func (r *Revoker) run() {
	defer close(r.done)
	for {
		select {
		case <-r.stopped:
			return
		case req := <-r.requests:
			res, err := r.handle(req)
			req.reply <- reply{res: res, err: err}
		}
	}
}

// handle performs one serialized read-modify-write pass on the role's
// revocation policy.
func (r *Revoker) handle(req request) (Result, error) {
	now := r.opts.Clock().UTC()
	res := Result{Role: req.role, PolicyName: r.opts.PolicyName}

	doc, err := r.load(req.ctx, req.role)
	if err != nil {
		return Result{}, err
	}

	// GC expired statements on every pass.
	kept := doc.Statement[:0]
	for _, st := range doc.Statement {
		if exp, ok := sidExpiry(st.Sid); ok && !exp.After(now) {
			res.RemovedSids = append(res.RemovedSids, st.Sid)
			continue
		}
		kept = append(kept, st)
	}
	doc.Statement = kept

	if req.stmt != nil {
		// Replace an existing statement with the same Sid.
		replaced := false
		for i := range doc.Statement {
			if doc.Statement[i].Sid == req.stmt.Sid {
				doc.Statement[i] = *req.stmt
				replaced = true
				break
			}
		}
		if !replaced {
			doc.Statement = append(doc.Statement, *req.stmt)
		}
		res.Sid = req.stmt.Sid
	}

	if len(doc.Statement) == 0 {
		err := r.writer.DeleteRolePolicy(req.ctx, req.role, r.opts.PolicyName)
		if err != nil && !errors.Is(err, ErrNoSuchPolicy) {
			return Result{}, fmt.Errorf("revoke: delete empty policy on role %s: %w", req.role, err)
		}
		res.Deleted = true
		return res, nil
	}

	sort.Slice(doc.Statement, func(i, j int) bool {
		return doc.Statement[i].Sid < doc.Statement[j].Sid
	})
	raw, err := json.Marshal(doc)
	if err != nil {
		return Result{}, fmt.Errorf("revoke: marshal policy: %w", err)
	}
	res.Statements = len(doc.Statement)
	res.PolicyChars = len(raw)
	if res.PolicyChars > MaxInlinePolicyChars {
		return Result{}, fmt.Errorf("%w: role %s, %d chars over the %d ceiling",
			ErrPolicyTooLarge, req.role, res.PolicyChars-MaxInlinePolicyChars, MaxInlinePolicyChars)
	}
	if res.PolicyChars > r.opts.WarnChars {
		res.Warned = true
		r.opts.Logger.Warn("revoke: revocation policy size crossed warn threshold",
			"role", req.role, "chars", res.PolicyChars, "warn_at", r.opts.WarnChars,
			"ceiling", MaxInlinePolicyChars)
	}
	if err := r.writer.PutRolePolicy(req.ctx, req.role, r.opts.PolicyName, string(raw)); err != nil {
		return Result{}, fmt.Errorf("revoke: put policy on role %s: %w", req.role, err)
	}
	return res, nil
}

// load reads and parses the current revocation policy for a role. A
// missing policy is an empty document.
func (r *Revoker) load(ctx context.Context, role string) (Document, error) {
	raw, err := r.writer.GetRolePolicy(ctx, role, r.opts.PolicyName)
	if errors.Is(err, ErrNoSuchPolicy) {
		return Document{Version: PolicyVersion}, nil
	}
	if err != nil {
		return Document{}, fmt.Errorf("revoke: get policy on role %s: %w", role, err)
	}
	var doc Document
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		// Never clobber a document this package cannot prove it wrote.
		return Document{}, fmt.Errorf("revoke: policy %s on role %s is not parseable, refusing to overwrite: %w",
			r.opts.PolicyName, role, err)
	}
	if doc.Version == "" {
		doc.Version = PolicyVersion
	}
	return doc, nil
}
