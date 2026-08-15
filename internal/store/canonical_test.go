package store

import (
	"fmt"
	"testing"
)

func TestCanonicalizeJSONStability(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "keys sort",
			in:   `{"b":1,"a":2}`,
			want: `{"a":2,"b":1}`,
		},
		{
			name: "nested keys sort",
			in:   `{"z":{"y":1,"x":{"c":true,"b":null}},"a":[3,2,1]}`,
			want: `{"a":[3,2,1],"z":{"x":{"b":null,"c":true},"y":1}}`,
		},
		{
			name: "whitespace removed",
			in:   "{\n  \"a\" : [ 1 , 2 ] ,\n  \"b\" : \"x\"\n}",
			want: `{"a":[1,2],"b":"x"}`,
		},
		{
			name: "number literals preserved",
			in:   `{"a":1.50,"b":1e3,"c":0.1000}`,
			want: `{"a":1.50,"b":1e3,"c":0.1000}`,
		},
		{
			name: "array order preserved",
			in:   `["b","a",{"k2":1,"k1":2}]`,
			want: `["b","a",{"k1":2,"k2":1}]`,
		},
		{
			name: "unicode string survives",
			in:   `{"t":"héllo é"}`,
			want: `{"t":"héllo é"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalizeJSON([]byte(tt.in))
			if err != nil {
				t.Fatalf("CanonicalizeJSON: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
			// Canonicalizing twice is a fixed point.
			again, err := CanonicalizeJSON(got)
			if err != nil {
				t.Fatalf("second CanonicalizeJSON: %v", err)
			}
			if string(again) != string(got) {
				t.Fatalf("not a fixed point: %s then %s", got, again)
			}
		})
	}
}

func TestCanonicalJSONMapOrderIndependence(t *testing.T) {
	// Build the same logical map many times; Go map iteration order
	// varies, canonical output must not.
	var first string
	for i := 0; i < 50; i++ {
		m := map[string]any{}
		for j := 0; j < 20; j++ {
			m[fmt.Sprintf("key-%02d", j)] = j
		}
		out, err := CanonicalJSON(m)
		if err != nil {
			t.Fatalf("CanonicalJSON: %v", err)
		}
		if first == "" {
			first = string(out)
			continue
		}
		if string(out) != first {
			t.Fatalf("iteration %d differs: %s vs %s", i, out, first)
		}
	}
}

func TestCanonicalizeJSONRejectsBadInput(t *testing.T) {
	for _, in := range []string{``, `{`, `{"a":1}extra`, `nope`} {
		if _, err := CanonicalizeJSON([]byte(in)); err == nil {
			t.Fatalf("input %q: want error, got none", in)
		}
	}
}
