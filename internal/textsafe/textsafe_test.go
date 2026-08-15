package textsafe

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello world", "hello world"},
		{"csi color", "a\x1b[31mred\x1b[0mb", "aredb"},
		{"osc title", "x\x1b]0;evil\x07y", "xy"},
		{"osc st terminated", "x\x1b]8;;http://e\x1b\\y", "xy"},
		{"bare c0", "a\x00b\x07c", "abc"},
		{"keeps newline and tab", "a\nb\tc", "a\nb\tc"},
		{"del", "a\x7fb", "ab"},
		{"trailing esc", "abc\x1b", "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sanitize(tt.in); got != tt.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"under budget", "short", 10, "short"},
		{"exact budget", "12345", 5, "12345"},
		{"over budget", "1234567890", 8, "12345..."},
		{"tiny budget", "abcdef", 2, "ab"},
		{"zero budget", "abc", 0, ""},
		{"multibyte", "日本語のテキスト", 5, "日本..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Truncate(tt.in, tt.max); got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

func TestSanitizeJSON(t *testing.T) {
	// The JSON text encodes ESC and BEL as \u escapes; after decoding,
	// the strings hold real control bytes, which must not survive.
	raw := []byte(`{"task":"read \u001b[31mdocs\u001b[0m","n":12345678901234567890,` +
		`"nested":{"\u001b[2Jkey":["a\u0007b",true,null,1.5]}}`)
	out, err := SanitizeJSON(raw)
	if err != nil {
		t.Fatalf("SanitizeJSON: %v", err)
	}
	if strings.Contains(string(out), "\\u001b") || strings.Contains(string(out), "\x1b") {
		t.Errorf("escape sequence survived: %s", out)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if v["task"] != "read docs" {
		t.Errorf("task = %q, want %q", v["task"], "read docs")
	}
	// Big integer precision must survive the round trip.
	if !strings.Contains(string(out), "12345678901234567890") {
		t.Errorf("number precision lost: %s", out)
	}
}

func TestSanitizeJSONInvalid(t *testing.T) {
	if _, err := SanitizeJSON([]byte(`{"broken":`)); err == nil {
		t.Error("want error for invalid JSON, got nil")
	}
}
