package broker

// Regression tests for the G8 capability-coverage cross-check: the
// rate, creep, and count controls key on the seam-reported capability
// ids, so the broker requires the policy's authoritative expansion to
// stay inside the union of those capabilities' catalog actions. A
// non-conforming seam that under-reports its selection while emitting
// a broader policy must be denied, not rate-limit-dodged.

import (
	"context"
	"strings"
	"testing"

	"github.com/0hardik1/taskgrant/internal/dataset"
	"github.com/0hardik1/taskgrant/internal/synth"
	"github.com/0hardik1/taskgrant/internal/synth/catalog"
)

func TestUncoveredActions(t *testing.T) {
	declared := map[string]struct{}{
		"s3:getobject":  {},
		"s3:listbucket": {},
	}
	cases := []struct {
		name     string
		expanded []string
		want     []string
	}{
		{"all_covered", []string{"s3:GetObject", "s3:ListBucket"}, nil},
		{"empty_expansion", nil, nil},
		{"one_uncovered", []string{"s3:GetObject", "s3:PutObject"}, []string{"s3:PutObject"}},
		{"all_uncovered_sorted", []string{"sqs:SendMessage", "lambda:InvokeFunction"},
			[]string{"lambda:InvokeFunction", "sqs:SendMessage"}},
		{"case_insensitive_cover", []string{"S3:GetObject"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := uncoveredActions(declared, tc.expanded)
			if len(got) != len(tc.want) {
				t.Fatalf("uncoveredActions = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("uncoveredActions[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}

	t.Run("empty_declared_set_covers_nothing", func(t *testing.T) {
		got := uncoveredActions(map[string]struct{}{}, []string{"s3:GetObject"})
		if len(got) != 1 || got[0] != "s3:GetObject" {
			t.Errorf("uncoveredActions = %v, want the single uncovered action", got)
		}
	})
}

// realCatalogStore loads the starter catalog over the pinned test
// dataset, exactly as the integration harness does.
func realCatalogStore(t *testing.T) *catalog.Store {
	t.Helper()
	ds, err := dataset.Load(integrationDatasetPath)
	if err != nil {
		t.Fatalf("dataset.Load: %v", err)
	}
	snap, err := catalog.Load(integrationCatalogDir, ds, catalog.WithoutGitCommit())
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	return catalog.NewStore(snap)
}

func TestRequestGrantDeniesUnderReportedCapabilities(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.cat = realCatalogStore(t)
		// The seam declares only s3.read-prefix, but the broker's own
		// expansion of the policy carries s3:PutObject (s3.write-prefix
		// material). The G8 ledgers would never see the write
		// capability; the coverage cross-check must deny.
		res := passResult()
		res.ExpandedActions = []string{"s3:GetObject", "s3:PutObject"}
		h.eval = &fakeEvaluator{res: res}
	})

	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "denied" {
		t.Fatalf("status = %q (detail %q), want denied", view.Status, view.Detail)
	}
	if view.DenialCode != "GUARDRAIL_VIOLATION" {
		t.Errorf("denial code = %q, want GUARDRAIL_VIOLATION", view.DenialCode)
	}
	if !strings.Contains(view.Detail, "s3:PutObject") {
		t.Errorf("detail %q does not name the uncovered action", view.Detail)
	}
	if h.mint.mints != 0 {
		t.Errorf("mint ran %d times on an uncovered policy, want 0", h.mint.mints)
	}
}

func TestRequestGrantCoveredCapabilitiesProceed(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.cat = realCatalogStore(t)
		// Declared s3.read-prefix covers both expanded actions.
		res := passResult()
		res.ExpandedActions = []string{"s3:GetObject", "s3:ListBucket"}
		h.eval = &fakeEvaluator{res: res}
	})

	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "active" {
		t.Fatalf("status = %q (detail %q, code %q), want active", view.Status, view.Detail, view.DenialCode)
	}
}

func TestRequestGrantOmittedCapabilityListDenied(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.cat = realCatalogStore(t)
		// A seam that reports no capabilities at all while emitting a
		// non-empty policy dodges every per-capability ledger; with a
		// catalog present that must fail coverage.
		h.synth = &fakeSynth{res: synth.Result{
			Verdict:         synth.VerdictPolicy,
			PolicyJSON:      []byte(testPolicy),
			ExpandedActions: []string{"s3:GetObject"},
		}}
	})

	view, err := h.b.RequestGrant(context.Background(), "bot", grantReq())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if view.Status != "denied" || view.DenialCode != "GUARDRAIL_VIOLATION" {
		t.Fatalf("status = %q code %q (detail %q), want denied GUARDRAIL_VIOLATION",
			view.Status, view.DenialCode, view.Detail)
	}
}
