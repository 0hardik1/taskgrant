package stsmint

import (
	"log/slog"
	"regexp"
)

// scrubKeyRE matches attribute keys that must never reach a log line.
var scrubKeyRE = regexp.MustCompile(`(?i)secret|token|authorization`)

// ScrubAttr is a slog HandlerOptions.ReplaceAttr function that drops
// every attribute whose key matches (?i)secret|token|authorization.
// The main binary installs it on the root handler as the second net
// behind the self-redacting Credentials type (section 8.7). Returning
// the zero Attr discards the attribute.
func ScrubAttr(groups []string, a slog.Attr) slog.Attr {
	if scrubKeyRE.MatchString(a.Key) {
		return slog.Attr{}
	}
	return a
}
