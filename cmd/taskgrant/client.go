package main

// client.go is the admin-socket HTTP client the CLI commands use to
// reach a running broker (approvals, approve/deny, revoke, creds).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// socketClient speaks HTTP over the admin unix socket.
type socketClient struct {
	http *http.Client
}

// newSocketClient dials the unix socket at path.
func newSocketClient(path string, timeout time.Duration) *socketClient {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &socketClient{
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", path)
				},
			},
		},
	}
}

// apiError is the adminapi error body.
type apiError struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
}

// do performs one request. A non-2xx answer returns the decoded API
// error; out may be nil to discard the body.
func (c *socketClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://taskgrant"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("admin socket: %w (is the broker running?)", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var ae apiError
		if json.Unmarshal(data, &ae) == nil && ae.Error != "" {
			return fmt.Errorf("%s: %s", ae.Error, ae.Detail)
		}
		return fmt.Errorf("admin api answered %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}
