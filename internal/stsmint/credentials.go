package stsmint

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// RedactedPlaceholder replaces secret material on every rendered
// surface of the Credentials type.
const RedactedPlaceholder = "[REDACTED]"

// Credentials is the record form of one minted session: safe to print,
// log, and serialize. String, GoString, MarshalJSON, and LogValue all
// redact the secret access key and the session token (invariant I4:
// the decision log stores the access key id only). The plaintext
// leaves the type exactly once, through Delivery.
type Credentials struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	expiration      time.Time
}

// NewCredentials builds a Credentials record. Only this package and
// tests should need it; production credentials come out of Mint.
func NewCredentials(accessKeyID, secretAccessKey, sessionToken string, expiration time.Time) Credentials {
	return Credentials{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		sessionToken:    sessionToken,
		expiration:      expiration,
	}
}

// AccessKeyID returns the access key id, the only credential component
// the decision log stores.
func (c Credentials) AccessKeyID() string { return c.accessKeyID }

// Expiration returns the credential expiry.
func (c Credentials) Expiration() time.Time { return c.expiration }

// String implements fmt.Stringer with the secret and token redacted.
func (c Credentials) String() string {
	return fmt.Sprintf("Credentials{AccessKeyID:%s SecretAccessKey:%s SessionToken:%s Expiration:%s}",
		c.accessKeyID, RedactedPlaceholder, RedactedPlaceholder,
		c.expiration.UTC().Format(time.RFC3339))
}

// GoString implements fmt.GoStringer so %#v cannot leak either.
func (c Credentials) GoString() string { return c.String() }

// MarshalJSON implements json.Marshaler with the secret and token
// redacted.
func (c Credentials) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AccessKeyID     string    `json:"access_key_id"`
		SecretAccessKey string    `json:"secret_access_key"`
		SessionToken    string    `json:"session_token"`
		Expiration      time.Time `json:"expiration"`
	}{
		AccessKeyID:     c.accessKeyID,
		SecretAccessKey: RedactedPlaceholder,
		SessionToken:    RedactedPlaceholder,
		Expiration:      c.expiration,
	})
}

// LogValue implements slog.LogValuer as a third net behind the
// Stringer and the ScrubAttr handler option.
func (c Credentials) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("access_key_id", c.accessKeyID),
		slog.Time("expiration", c.expiration),
	)
}

// Delivery carries the plaintext credentials exactly once to the
// requesting agent (invariant I4). It must never be logged or stored;
// build it at the delivery boundary and let it go out of scope. Field
// names follow the AWS credential_process JSON shape.
type Delivery struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
}

// Delivery returns the plaintext form for the one-time hand-off to the
// requesting agent.
func (c Credentials) Delivery() Delivery {
	return Delivery{
		AccessKeyID:     c.accessKeyID,
		SecretAccessKey: c.secretAccessKey,
		SessionToken:    c.sessionToken,
		Expiration:      c.expiration,
	}
}
