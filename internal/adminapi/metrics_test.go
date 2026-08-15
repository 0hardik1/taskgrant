package adminapi

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMetricsPrometheusFormat(t *testing.T) {
	m := NewMetrics()
	m.now = func() time.Time { return time.Unix(2000, 0) }
	m.IncGrantOutcome("auto_approved")
	m.IncGrantOutcome("auto_approved")
	m.IncGrantOutcome("denied")
	m.IncGrantOutcome("weird-unknown-outcome")
	m.ObservePackedPolicySize(72)
	m.ObserveApprovalLatency(4 * time.Second)
	m.ObserveApprovalLatency(45 * time.Second)
	m.ObserveApprovalLatency(2 * time.Hour) // lands in +Inf
	m.SetAnchorSuccess(time.Unix(1000, 0))

	var sb strings.Builder
	if err := m.WritePrometheus(&sb); err != nil {
		t.Fatalf("WritePrometheus: %v", err)
	}
	out := sb.String()

	wantLines := []string{
		`taskgrant_grants_total{outcome="auto_approved"} 2`,
		`taskgrant_grants_total{outcome="denied"} 1`,
		`taskgrant_grants_total{outcome="other"} 1`,
		`taskgrant_packed_policy_size_percent 72`,
		`taskgrant_approval_latency_seconds_bucket{le="5"} 1`,
		`taskgrant_approval_latency_seconds_bucket{le="60"} 2`,
		`taskgrant_approval_latency_seconds_bucket{le="+Inf"} 3`,
		`taskgrant_approval_latency_seconds_count 3`,
		`taskgrant_anchor_last_success_timestamp_seconds 1000`,
		`taskgrant_anchor_age_seconds 1000`,
	}
	for _, line := range wantLines {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing line %q in output:\n%s", line, out)
		}
	}

	// Every metric family needs HELP and TYPE headers before samples.
	for _, family := range []string{
		"taskgrant_grants_total",
		"taskgrant_packed_policy_size_percent",
		"taskgrant_approval_latency_seconds",
		"taskgrant_anchor_last_success_timestamp_seconds",
	} {
		if !strings.Contains(out, "# HELP "+family+" ") {
			t.Errorf("missing HELP for %s", family)
		}
		if !strings.Contains(out, "# TYPE "+family+" ") {
			t.Errorf("missing TYPE for %s", family)
		}
	}

	// Histogram sum should be 4 + 45 + 7200 seconds.
	sumRE := regexp.MustCompile(`taskgrant_approval_latency_seconds_sum ([0-9.]+)\n`)
	match := sumRE.FindStringSubmatch(out)
	if match == nil {
		t.Fatalf("no histogram sum in output:\n%s", out)
	}
	if match[1] != "7249" {
		t.Errorf("histogram sum = %s, want 7249", match[1])
	}

	// Buckets must be cumulative and non-decreasing.
	bucketRE := regexp.MustCompile(`taskgrant_approval_latency_seconds_bucket\{le="[^"]+"\} ([0-9]+)`)
	prev := -1
	for _, m := range bucketRE.FindAllStringSubmatch(out, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("bucket value %q: %v", m[1], err)
		}
		if n < prev {
			t.Errorf("bucket counts decreased: %d after %d", n, prev)
		}
		prev = n
	}
}

func TestMetricsNeverAnchored(t *testing.T) {
	m := NewMetrics()
	var sb strings.Builder
	if err := m.WritePrometheus(&sb); err != nil {
		t.Fatalf("WritePrometheus: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "taskgrant_anchor_last_success_timestamp_seconds 0\n") {
		t.Errorf("expected zero anchor timestamp:\n%s", out)
	}
	if strings.Contains(out, "taskgrant_anchor_age_seconds") {
		t.Errorf("age gauge must be absent before the first anchor:\n%s", out)
	}
}
