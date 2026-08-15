package compile

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// Regenerate the golden corpus with:
//
//	go test ./internal/synth/compile -run Golden -update
//
// Golden bytes are the CI contract for invariant I6: the same
// capability set and params must compile to byte-identical JSON on
// every machine and every run.
var update = flag.Bool("update", false, "rewrite golden files")

type goldenCase struct {
	name  string
	build func(t *testing.T) (Input, *Compiler)
}

func goldenCases(t *testing.T) []goldenCase {
	t.Helper()
	_, snap, c := loadEnv(t)
	return []goldenCase{
		{
			name: "s3-read-prefix",
			build: func(t *testing.T) (Input, *Compiler) {
				return baseInput(
					selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}),
				), c
			},
		},
		{
			name: "three-capabilities",
			build: func(t *testing.T) (Input, *Compiler) {
				return baseInput(
					selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}),
					selection(t, snap, "dynamodb.query", map[string]string{"table": "invoices"}),
					selection(t, snap, "sqs.produce", map[string]string{"queue": "invoice-events"}),
				), c
			},
		},
		{
			name: "ladder-offload",
			build: func(t *testing.T) (Input, *Compiler) {
				in := baseInput(
					selection(t, snap, "s3.read-prefix", map[string]string{"bucket": "acme-invoices-prod", "prefix": "2026/"}),
					selection(t, snap, "logs.read", map[string]string{"log_group": "/aws/lambda/invoice-processor"}),
				)
				in.MaxPolicyChars = 700
				return in, c
			},
		},
	}
}

func TestGoldenCorpus(t *testing.T) {
	for _, gc := range goldenCases(t) {
		t.Run(gc.name, func(t *testing.T) {
			in, c := gc.build(t)
			out, err := c.Compile(in)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			path := filepath.Join("testdata", "golden", gc.name+".json")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, out.PolicyJSON, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden file (regenerate with -update): %v", err)
			}
			if !bytes.Equal(out.PolicyJSON, want) {
				t.Errorf("compiled bytes diverge from golden corpus (I6)\n got: %s\nwant: %s", out.PolicyJSON, want)
			}
			// The golden policies must fit the section 7.1 plaintext
			// ceiling with tag headroom.
			if out.Chars > 2048-300 {
				t.Errorf("golden policy is %d chars, over the budget ceiling", out.Chars)
			}
		})
	}
}
