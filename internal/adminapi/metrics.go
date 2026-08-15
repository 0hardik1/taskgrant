package adminapi

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
)

// Metrics is the process-wide metrics registry (section 15): grant
// totals by outcome, packed-policy-size headroom, approval latency, and
// anchor freshness. It is a plain struct of atomics so any package can
// increment without importing a metrics client; /metrics renders the
// Prometheus text exposition format by hand.
type Metrics struct {
	grantOutcomes map[string]*atomic.Uint64

	// packedPolicySizePct is the last observed PackedPolicySize
	// percentage from STS (section 7.3: warn at 70, alert at 85).
	packedPolicySizePct atomic.Int64
	packedPolicySeen    atomic.Bool

	approvalLatency histogram

	// anchorLastSuccess is the unix time of the last successful
	// external log anchor write (section 9.3); 0 until the first one.
	anchorLastSuccess atomic.Int64

	now func() time.Time
}

// grantOutcomeKeys is the fixed label set for taskgrant_grants_total.
// A fixed set keeps label cardinality bounded no matter what callers
// pass; unknown outcomes count under "other".
var grantOutcomeKeys = []string{
	"auto_approved",
	"pending_approval",
	"approved",
	"needs_clarification",
	"denied",
	"error",
	"minted",
	"expired",
	"expired_pending",
	"released",
	"other",
}

// approvalLatencyBounds are the histogram bucket upper bounds in
// seconds. Approvals are human-paced; the top explicit bucket matches
// the default pending TTL (900 s).
var approvalLatencyBounds = []float64{1, 5, 15, 30, 60, 120, 300, 600, 900}

type histogram struct {
	bounds    []float64
	counts    []atomic.Uint64 // len(bounds)+1, last is +Inf
	sumMicros atomic.Int64
	count     atomic.Uint64
}

func (h *histogram) observe(seconds float64) {
	i := sort.SearchFloat64s(h.bounds, seconds)
	h.counts[i].Add(1)
	h.sumMicros.Add(int64(seconds * 1e6))
	h.count.Add(1)
}

// NewMetrics builds an empty registry.
func NewMetrics() *Metrics {
	m := &Metrics{
		grantOutcomes: make(map[string]*atomic.Uint64, len(grantOutcomeKeys)),
		now:           time.Now,
	}
	for _, k := range grantOutcomeKeys {
		m.grantOutcomes[k] = new(atomic.Uint64)
	}
	m.approvalLatency.bounds = approvalLatencyBounds
	m.approvalLatency.counts = make([]atomic.Uint64, len(approvalLatencyBounds)+1)
	return m
}

// IncGrantOutcome counts one grant decision by outcome. Outcomes
// outside the fixed set count as "other".
func (m *Metrics) IncGrantOutcome(outcome string) {
	c, ok := m.grantOutcomes[outcome]
	if !ok {
		c = m.grantOutcomes["other"]
	}
	c.Add(1)
}

// ObservePackedPolicySize records the PackedPolicySize percentage STS
// reported for a successful mint.
func (m *Metrics) ObservePackedPolicySize(percent int) {
	m.packedPolicySizePct.Store(int64(percent))
	m.packedPolicySeen.Store(true)
}

// ObserveApprovalLatency records the time from pending_approval to a
// human decision.
func (m *Metrics) ObserveApprovalLatency(d time.Duration) {
	if d < 0 {
		d = 0
	}
	m.approvalLatency.observe(d.Seconds())
}

// SetAnchorSuccess records a successful external anchor write.
func (m *Metrics) SetAnchorSuccess(at time.Time) {
	m.anchorLastSuccess.Store(at.Unix())
}

// WritePrometheus renders the registry in Prometheus text exposition
// format (version 0.0.4), written by hand per the ground rules: no
// client library.
func (m *Metrics) WritePrometheus(w io.Writer) error {
	var err error
	p := func(format string, args ...any) {
		if err == nil {
			_, err = fmt.Fprintf(w, format, args...)
		}
	}

	p("# HELP taskgrant_grants_total Grant decisions by outcome.\n")
	p("# TYPE taskgrant_grants_total counter\n")
	for _, k := range grantOutcomeKeys {
		p("taskgrant_grants_total{outcome=%q} %d\n", k, m.grantOutcomes[k].Load())
	}

	p("# HELP taskgrant_packed_policy_size_percent Last observed STS PackedPolicySize percentage.\n")
	p("# TYPE taskgrant_packed_policy_size_percent gauge\n")
	if m.packedPolicySeen.Load() {
		p("taskgrant_packed_policy_size_percent %d\n", m.packedPolicySizePct.Load())
	} else {
		p("taskgrant_packed_policy_size_percent 0\n")
	}

	p("# HELP taskgrant_approval_latency_seconds Time from pending_approval to a human decision.\n")
	p("# TYPE taskgrant_approval_latency_seconds histogram\n")
	var cumulative uint64
	for i, bound := range m.approvalLatency.bounds {
		cumulative += m.approvalLatency.counts[i].Load()
		p("taskgrant_approval_latency_seconds_bucket{le=%q} %d\n", formatFloat(bound), cumulative)
	}
	cumulative += m.approvalLatency.counts[len(m.approvalLatency.bounds)].Load()
	p("taskgrant_approval_latency_seconds_bucket{le=\"+Inf\"} %d\n", cumulative)
	p("taskgrant_approval_latency_seconds_sum %s\n",
		formatFloat(float64(m.approvalLatency.sumMicros.Load())/1e6))
	p("taskgrant_approval_latency_seconds_count %d\n", m.approvalLatency.count.Load())

	p("# HELP taskgrant_anchor_last_success_timestamp_seconds Unix time of the last successful log anchor write; 0 when never anchored.\n")
	p("# TYPE taskgrant_anchor_last_success_timestamp_seconds gauge\n")
	last := m.anchorLastSuccess.Load()
	p("taskgrant_anchor_last_success_timestamp_seconds %d\n", last)

	if last > 0 {
		age := m.now().Unix() - last
		if age < 0 {
			age = 0
		}
		p("# HELP taskgrant_anchor_age_seconds Seconds since the last successful log anchor write.\n")
		p("# TYPE taskgrant_anchor_age_seconds gauge\n")
		p("taskgrant_anchor_age_seconds %d\n", age)
	}
	return err
}

// formatFloat renders a float the way Prometheus expects: no exponent
// for the values in play, no trailing zeros.
func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}
