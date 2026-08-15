package revoke

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/store"
)

// iamAPIVersion is the IAM Query API version.
const iamAPIVersion = "2010-05-08"

// IAMWriterOptions configures NewIAMPolicyWriter.
type IAMWriterOptions struct {
	// EndpointURL overrides the IAM endpoint (aws.endpoint_url support,
	// for LocalStack). Empty selects https://iam.amazonaws.com.
	EndpointURL string
	// Region is the signing region. IAM is global; the default
	// us-east-1 is correct for the standard partition.
	Region      string
	Credentials store.AWSCredentialsProvider
	HTTPClient  *http.Client
}

// IAMPolicyWriter is the production PolicyWriter: signed HTTP calls to
// the IAM Query API (PutRolePolicy, GetRolePolicy, DeleteRolePolicy).
type IAMPolicyWriter struct {
	opts IAMWriterOptions
	base string
}

var _ PolicyWriter = (*IAMPolicyWriter)(nil)

// NewIAMPolicyWriter validates options and returns the writer.
func NewIAMPolicyWriter(opts IAMWriterOptions) (*IAMPolicyWriter, error) {
	if opts.Credentials == nil {
		return nil, errors.New("revoke: iam writer requires credentials")
	}
	if opts.Region == "" {
		opts.Region = "us-east-1"
	}
	base := opts.EndpointURL
	if base == "" {
		base = "https://iam.amazonaws.com"
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("revoke: iam endpoint %q is not a valid http(s) URL", base)
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &IAMPolicyWriter{opts: opts, base: strings.TrimRight(base, "/")}, nil
}

// PutRolePolicy implements PolicyWriter.
func (w *IAMPolicyWriter) PutRolePolicy(ctx context.Context, roleName, policyName, document string) error {
	_, err := w.call(ctx, url.Values{
		"Action":         {"PutRolePolicy"},
		"Version":        {iamAPIVersion},
		"RoleName":       {roleName},
		"PolicyName":     {policyName},
		"PolicyDocument": {document},
	})
	return err
}

// getRolePolicyResponse is the XML shape of a GetRolePolicy result.
type getRolePolicyResponse struct {
	Result struct {
		PolicyDocument string `xml:"PolicyDocument"`
	} `xml:"GetRolePolicyResult"`
}

// GetRolePolicy implements PolicyWriter. The document returns as plain
// JSON; IAM's URL encoding is reversed here.
func (w *IAMPolicyWriter) GetRolePolicy(ctx context.Context, roleName, policyName string) (string, error) {
	body, err := w.call(ctx, url.Values{
		"Action":     {"GetRolePolicy"},
		"Version":    {iamAPIVersion},
		"RoleName":   {roleName},
		"PolicyName": {policyName},
	})
	if err != nil {
		return "", err
	}
	var resp getRolePolicyResponse
	if err := xml.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("revoke: iam GetRolePolicy response: %w", err)
	}
	doc, err := url.QueryUnescape(resp.Result.PolicyDocument)
	if err != nil {
		return "", fmt.Errorf("revoke: iam policy document decode: %w", err)
	}
	return doc, nil
}

// DeleteRolePolicy implements PolicyWriter.
func (w *IAMPolicyWriter) DeleteRolePolicy(ctx context.Context, roleName, policyName string) error {
	_, err := w.call(ctx, url.Values{
		"Action":     {"DeleteRolePolicy"},
		"Version":    {iamAPIVersion},
		"RoleName":   {roleName},
		"PolicyName": {policyName},
	})
	return err
}

// iamErrorResponse is the XML error shape of the Query API.
type iamErrorResponse struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// call performs one signed IAM Query API call and returns the response
// body on success.
func (w *IAMPolicyWriter) call(ctx context.Context, form url.Values) ([]byte, error) {
	payload := []byte(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.base+"/", strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("revoke: iam request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	creds, err := w.opts.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("revoke: iam credentials: %w", err)
	}
	if err := store.SignV4(req, creds, "iam", w.opts.Region, store.SHA256Hex(payload), time.Now()); err != nil {
		return nil, fmt.Errorf("revoke: iam sign: %w", err)
	}
	resp, err := w.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("revoke: iam call: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("revoke: iam response: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return body, nil
	}
	var e iamErrorResponse
	if xml.Unmarshal(body, &e) == nil && e.Error.Code == "NoSuchEntity" {
		return nil, ErrNoSuchPolicy
	}
	action := form.Get("Action")
	if e.Error.Code != "" {
		return nil, fmt.Errorf("revoke: iam %s: %s: %s", action, e.Error.Code, e.Error.Message)
	}
	return nil, fmt.Errorf("revoke: iam %s: status %d", action, resp.StatusCode)
}
