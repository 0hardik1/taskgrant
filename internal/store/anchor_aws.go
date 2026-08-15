package store

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The AWS anchorers write checkpoints as signed HTTP calls (SigV4, see
// awssign.go). Each destination accepts writes but resists deletion:
// S3 Object Lock retention, or a CloudWatch Logs stream written by a
// principal without delete permissions.

// S3AnchorOptions configures NewS3ObjectLockAnchorer. The bucket should
// enforce Object Lock with a default retention so written checkpoints
// cannot be deleted or overwritten inside the retention window.
type S3AnchorOptions struct {
	Bucket string
	// Prefix prepends every object key, for example "taskgrant/anchor/".
	Prefix string
	Region string
	// EndpointURL overrides the S3 endpoint (aws.endpoint_url support,
	// for LocalStack and compatible stores). Empty selects
	// https://s3.<region>.amazonaws.com with path-style addressing.
	EndpointURL string
	Credentials AWSCredentialsProvider
	HTTPClient  *http.Client
	// RetainFor, when positive, sets per-object Object Lock retention
	// of the given duration in ObjectLockMode.
	RetainFor time.Duration
	// ObjectLockMode is COMPLIANCE (default) or GOVERNANCE; used only
	// when RetainFor is positive.
	ObjectLockMode string
}

// S3ObjectLockAnchorer writes one checkpoint object per anchor tick to
// an Object Lock bucket.
type S3ObjectLockAnchorer struct {
	opts   S3AnchorOptions
	base   string
	client *http.Client
}

// NewS3ObjectLockAnchorer validates options and returns the anchorer.
func NewS3ObjectLockAnchorer(opts S3AnchorOptions) (*S3ObjectLockAnchorer, error) {
	if opts.Bucket == "" {
		return nil, errors.New("store: s3 anchorer requires a bucket")
	}
	if opts.Region == "" {
		return nil, errors.New("store: s3 anchorer requires a region")
	}
	if opts.Credentials == nil {
		return nil, errors.New("store: s3 anchorer requires credentials")
	}
	base := opts.EndpointURL
	if base == "" {
		base = fmt.Sprintf("https://s3.%s.amazonaws.com", opts.Region)
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("store: s3 anchorer endpoint %q is not a valid http(s) URL", base)
	}
	if opts.ObjectLockMode == "" {
		opts.ObjectLockMode = "COMPLIANCE"
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &S3ObjectLockAnchorer{
		opts:   opts,
		base:   strings.TrimRight(base, "/"),
		client: client,
	}, nil
}

// Anchor puts one checkpoint object. The key embeds timestamp and seq,
// so successive checkpoints never collide and never overwrite.
func (a *S3ObjectLockAnchorer) Anchor(ctx context.Context, cp Checkpoint) error {
	body, err := CanonicalJSON(cp)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%scheckpoint-%s-seq%d.json",
		a.opts.Prefix, cp.Timestamp.UTC().Format("20060102T150405Z"), cp.Seq)
	// Path-style addressing works for both AWS and endpoint overrides.
	target := a.base + "/" + a.opts.Bucket + "/" + pathEscapeKey(key)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("store: s3 anchor request: %w", err)
	}
	payloadHash := SHA256Hex(body)
	md5sum := md5.Sum(body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	// Object Lock puts require Content-MD5.
	req.Header.Set("Content-Md5", base64.StdEncoding.EncodeToString(md5sum[:]))
	if a.opts.RetainFor > 0 {
		req.Header.Set("X-Amz-Object-Lock-Mode", a.opts.ObjectLockMode)
		req.Header.Set("X-Amz-Object-Lock-Retain-Until-Date",
			cp.Timestamp.UTC().Add(a.opts.RetainFor).Format(time.RFC3339))
	}

	creds, err := a.opts.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("store: s3 anchor credentials: %w", err)
	}
	if err := SignV4(req, creds, "s3", a.opts.Region, payloadHash, time.Now()); err != nil {
		return fmt.Errorf("store: s3 anchor sign: %w", err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("store: s3 anchor put: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("store: s3 anchor put %s: %s", key, httpErrorDetail(resp))
	}
	return nil
}

// pathEscapeKey escapes an object key per segment, keeping slashes.
func pathEscapeKey(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// CloudWatchLogsAnchorOptions configures NewCloudWatchLogsAnchorer.
type CloudWatchLogsAnchorOptions struct {
	LogGroup string
	// LogStream defaults to "taskgrant-anchor".
	LogStream string
	Region    string
	// EndpointURL overrides the CloudWatch Logs endpoint. Empty selects
	// https://logs.<region>.amazonaws.com.
	EndpointURL string
	Credentials AWSCredentialsProvider
	HTTPClient  *http.Client
}

// CloudWatchLogsAnchorer appends checkpoints as log events. A log
// stream is append-only for a writer without delete permissions, which
// is the property the anchor needs.
type CloudWatchLogsAnchorer struct {
	opts   CloudWatchLogsAnchorOptions
	base   string
	client *http.Client
}

// NewCloudWatchLogsAnchorer validates options and returns the anchorer.
func NewCloudWatchLogsAnchorer(opts CloudWatchLogsAnchorOptions) (*CloudWatchLogsAnchorer, error) {
	if opts.LogGroup == "" {
		return nil, errors.New("store: cloudwatch logs anchorer requires a log group")
	}
	if opts.Region == "" {
		return nil, errors.New("store: cloudwatch logs anchorer requires a region")
	}
	if opts.Credentials == nil {
		return nil, errors.New("store: cloudwatch logs anchorer requires credentials")
	}
	if opts.LogStream == "" {
		opts.LogStream = "taskgrant-anchor"
	}
	base := opts.EndpointURL
	if base == "" {
		base = fmt.Sprintf("https://logs.%s.amazonaws.com", opts.Region)
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("store: cloudwatch logs anchorer endpoint %q is not a valid http(s) URL", base)
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &CloudWatchLogsAnchorer{
		opts:   opts,
		base:   strings.TrimRight(base, "/"),
		client: client,
	}, nil
}

// Anchor puts one log event carrying the checkpoint JSON. A missing
// log stream is created once and the put retried.
func (a *CloudWatchLogsAnchorer) Anchor(ctx context.Context, cp Checkpoint) error {
	msg, err := CanonicalJSON(cp)
	if err != nil {
		return err
	}
	put := map[string]any{
		"logGroupName":  a.opts.LogGroup,
		"logStreamName": a.opts.LogStream,
		"logEvents": []map[string]any{{
			"timestamp": cp.Timestamp.UTC().UnixMilli(),
			"message":   string(msg),
		}},
	}
	status, respBody, err := a.rpc(ctx, "Logs_20140328.PutLogEvents", put)
	if err != nil {
		return err
	}
	if status >= 200 && status <= 299 {
		return nil
	}
	if isCWLResourceNotFound(respBody) {
		create := map[string]any{
			"logGroupName":  a.opts.LogGroup,
			"logStreamName": a.opts.LogStream,
		}
		cStatus, cBody, err := a.rpc(ctx, "Logs_20140328.CreateLogStream", create)
		if err != nil {
			return err
		}
		// ResourceAlreadyExistsException is fine: another writer won.
		if (cStatus < 200 || cStatus > 299) && !bytes.Contains(cBody, []byte("ResourceAlreadyExistsException")) {
			return fmt.Errorf("store: cloudwatch logs create stream: status %d: %s", cStatus, truncateBytes(cBody, 512))
		}
		status, respBody, err = a.rpc(ctx, "Logs_20140328.PutLogEvents", put)
		if err != nil {
			return err
		}
		if status >= 200 && status <= 299 {
			return nil
		}
	}
	return fmt.Errorf("store: cloudwatch logs put events: status %d: %s", status, truncateBytes(respBody, 512))
}

// rpc performs one signed CloudWatch Logs JSON-RPC call.
func (a *CloudWatchLogsAnchorer) rpc(ctx context.Context, target string, payload any) (int, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, fmt.Errorf("store: cloudwatch logs payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+"/", bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("store: cloudwatch logs request: %w", err)
	}
	payloadHash := SHA256Hex(body)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)

	creds, err := a.opts.Credentials.Retrieve(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("store: cloudwatch logs credentials: %w", err)
	}
	if err := SignV4(req, creds, "logs", a.opts.Region, payloadHash, time.Now()); err != nil {
		return 0, nil, fmt.Errorf("store: cloudwatch logs sign: %w", err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("store: cloudwatch logs call: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("store: cloudwatch logs response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

// isCWLResourceNotFound detects the ResourceNotFoundException error
// shape of the CloudWatch Logs JSON protocol.
func isCWLResourceNotFound(body []byte) bool {
	var e struct {
		Type string `json:"__type"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return false
	}
	return strings.Contains(e.Type, "ResourceNotFoundException")
}

func httpErrorDetail(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Sprintf("status %d: %s", resp.StatusCode, truncateBytes(b, 512))
}

func truncateBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}
