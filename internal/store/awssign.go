package store

// AWS SigV4 request signing with the standard library. The module's
// dependency set carries no AWS SDK, and the anchor and revocation
// paths each need only a small number of signed HTTP calls, so the
// signer lives here and the sibling packages import it.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// AWSCredentials is one set of AWS credentials. SessionToken is empty
// for long-lived keys.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// AWSCredentialsProvider yields credentials for signing. Implementations
// must be safe for concurrent use.
type AWSCredentialsProvider interface {
	Retrieve(ctx context.Context) (AWSCredentials, error)
}

// StaticCredentialsProvider returns fixed credentials.
type StaticCredentialsProvider struct {
	Credentials AWSCredentials
}

// Retrieve implements AWSCredentialsProvider.
func (p StaticCredentialsProvider) Retrieve(context.Context) (AWSCredentials, error) {
	if p.Credentials.AccessKeyID == "" || p.Credentials.SecretAccessKey == "" {
		return AWSCredentials{}, errors.New("store: static credentials are empty")
	}
	return p.Credentials, nil
}

// EnvCredentialsProvider reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
// and AWS_SESSION_TOKEN from the environment on every call.
type EnvCredentialsProvider struct{}

// Retrieve implements AWSCredentialsProvider.
func (EnvCredentialsProvider) Retrieve(context.Context) (AWSCredentials, error) {
	c := AWSCredentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return AWSCredentials{}, errors.New("store: AWS credentials not present in environment")
	}
	return c, nil
}

// UnsignedPayload is the payload hash sentinel for streaming bodies.
const UnsignedPayload = "UNSIGNED-PAYLOAD"

// SignV4 signs req in place with AWS Signature Version 4. payloadHash
// is the hex SHA-256 of the request body (or UnsignedPayload). The
// function sets X-Amz-Date, X-Amz-Security-Token when the credentials
// carry one, and Authorization. Every header already present on the
// request is included in the signature.
func SignV4(req *http.Request, creds AWSCredentials, service, region, payloadHash string, now time.Time) error {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return errors.New("store: sigv4 requires credentials")
	}
	if service == "" || region == "" {
		return errors.New("store: sigv4 requires service and region")
	}
	if payloadHash == "" {
		return errors.New("store: sigv4 requires a payload hash")
	}
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Canonical headers: every present header plus host, lowercased,
	// sorted, values trimmed and space-collapsed.
	headers := map[string]string{"host": host}
	for name, values := range req.Header {
		headers[strings.ToLower(name)] = collapseSpaces(strings.Join(values, ","))
	}
	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		canonHeaders.WriteString(n)
		canonHeaders.WriteByte(':')
		canonHeaders.WriteString(headers[n])
		canonHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")

	canonURI := req.URL.EscapedPath()
	if canonURI == "" {
		canonURI = "/"
	}
	canonQuery := canonicalQuery(req.URL.Query())

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonURI,
		canonQuery,
		canonHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	crSum := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(crSum[:]),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, scope, signedHeaders, signature))
	return nil
}

// canonicalQuery renders query values in SigV4 canonical form: keys and
// values RFC 3986 encoded, sorted by key then value.
func canonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, kv{uriEncode(k), uriEncode(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.k+"="+p.v)
	}
	return strings.Join(parts, "&")
}

// uriEncode implements the SigV4 URI encoding rules: unreserved
// characters stay, everything else percent-encodes with uppercase hex.
func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// collapseSpaces trims and collapses sequential spaces per the SigV4
// canonical header rules.
func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// SHA256Hex returns the hex SHA-256 of data; the payload hash form
// SigV4 expects.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
