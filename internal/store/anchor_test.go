package store

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testHMACKey = []byte("test-anchor-hmac-key")

func TestCheckpointSignAndVerify(t *testing.T) {
	s := openTestStore(t, Options{})
	appendDecision(t, s, "invoice-bot", "anchor me", time.Now().UTC())

	cp, err := s.Checkpoint(testHMACKey)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if cp.Seq != 1 || cp.RecordCount != 1 || cp.Hash == "" || cp.Signature == "" {
		t.Fatalf("checkpoint incomplete: %+v", cp)
	}
	if !VerifyCheckpoint(cp, testHMACKey) {
		t.Fatal("valid checkpoint failed verification")
	}
	tampered := cp
	tampered.Hash = GenesisHash
	if VerifyCheckpoint(tampered, testHMACKey) {
		t.Fatal("tampered checkpoint verified")
	}
	if VerifyCheckpoint(cp, []byte("wrong-key")) {
		t.Fatal("wrong key verified")
	}
}

func TestCheckpointEmptyStore(t *testing.T) {
	s := openTestStore(t, Options{})
	cp, err := s.Checkpoint(testHMACKey)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if cp.Seq != 0 || cp.Hash != GenesisHash || cp.RecordCount != 0 {
		t.Fatalf("empty checkpoint: %+v", cp)
	}
}

func TestFileAnchorer(t *testing.T) {
	s := openTestStore(t, Options{})
	appendDecision(t, s, "invoice-bot", "anchor me", time.Now().UTC())
	path := filepath.Join(t.TempDir(), "anchors", "chain.jsonl")
	a, err := NewFileAnchorer(path)
	if err != nil {
		t.Fatalf("NewFileAnchorer: %v", err)
	}
	for i := 0; i < 2; i++ {
		cp, err := s.Checkpoint(testHMACKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Anchor(context.Background(), cp); err != nil {
			t.Fatalf("Anchor: %v", err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open anchors: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	lines := 0
	for sc.Scan() {
		lines++
		var cp Checkpoint
		if err := json.Unmarshal(sc.Bytes(), &cp); err != nil {
			t.Fatalf("anchor line %d: %v", lines, err)
		}
		if !VerifyCheckpoint(cp, testHMACKey) {
			t.Fatalf("anchor line %d failed HMAC verification", lines)
		}
	}
	if lines != 2 {
		t.Fatalf("anchor lines %d, want 2", lines)
	}
}

func TestAnchorLoopWritesAndStops(t *testing.T) {
	s := openTestStore(t, Options{})
	appendDecision(t, s, "invoice-bot", "anchor me", time.Now().UTC())
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	a, err := NewFileAnchorer(path)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := s.StartAnchorLoop(a, 50*time.Millisecond, testHMACKey)
	if err != nil {
		t.Fatalf("StartAnchorLoop: %v", err)
	}
	// A second loop must refuse.
	if _, err := s.StartAnchorLoop(a, time.Hour, testHMACKey); err == nil {
		t.Fatal("second anchor loop started")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, _ := os.ReadFile(path)
		if strings.Count(string(data), "\n") >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("anchor loop wrote fewer than 2 checkpoints in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	// A new loop may start after stop.
	stop2, err := s.StartAnchorLoop(a, time.Hour, testHMACKey)
	if err != nil {
		t.Fatalf("restart anchor loop: %v", err)
	}
	stop2()
}

func TestS3ObjectLockAnchorer(t *testing.T) {
	type captured struct {
		method, path  string
		auth          string
		contentSHA    string
		contentMD5    string
		lockMode      string
		lockRetain    string
		securityToken string
		body          []byte
	}
	var got captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = captured{
			method:        r.Method,
			path:          r.URL.Path,
			auth:          r.Header.Get("Authorization"),
			contentSHA:    r.Header.Get("X-Amz-Content-Sha256"),
			contentMD5:    r.Header.Get("Content-Md5"),
			lockMode:      r.Header.Get("X-Amz-Object-Lock-Mode"),
			lockRetain:    r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"),
			securityToken: r.Header.Get("X-Amz-Security-Token"),
			body:          body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a, err := NewS3ObjectLockAnchorer(S3AnchorOptions{
		Bucket:      "acme-taskgrant-anchor",
		Prefix:      "taskgrant/",
		Region:      "us-east-1",
		EndpointURL: srv.URL,
		Credentials: StaticCredentialsProvider{Credentials: AWSCredentials{
			AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret", SessionToken: "token",
		}},
		RetainFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewS3ObjectLockAnchorer: %v", err)
	}
	cp := Checkpoint{Seq: 7, Hash: "abc", RecordCount: 7,
		Timestamp: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC), Signature: "sig"}
	if err := a.Anchor(context.Background(), cp); err != nil {
		t.Fatalf("Anchor: %v", err)
	}

	if got.method != http.MethodPut {
		t.Fatalf("method %s", got.method)
	}
	wantPath := "/acme-taskgrant-anchor/taskgrant/checkpoint-20260814T120000Z-seq7.json"
	if got.path != wantPath {
		t.Fatalf("path %s, want %s", got.path, wantPath)
	}
	if !strings.HasPrefix(got.auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20") {
		t.Fatalf("authorization: %s", got.auth)
	}
	if !strings.Contains(got.auth, "/us-east-1/s3/aws4_request") {
		t.Fatalf("authorization scope: %s", got.auth)
	}
	if got.contentSHA != SHA256Hex(got.body) {
		t.Fatal("content sha mismatch")
	}
	if got.contentMD5 == "" {
		t.Fatal("Content-MD5 missing (Object Lock puts require it)")
	}
	if got.lockMode != "COMPLIANCE" || got.lockRetain == "" {
		t.Fatalf("object lock headers: mode=%q retain=%q", got.lockMode, got.lockRetain)
	}
	if got.securityToken != "token" {
		t.Fatal("session token header missing")
	}
	var sent Checkpoint
	if err := json.Unmarshal(got.body, &sent); err != nil || sent.Seq != 7 {
		t.Fatalf("body: %s err=%v", got.body, err)
	}
}

func TestCloudWatchLogsAnchorerCreatesStream(t *testing.T) {
	var targets []string
	streamExists := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		targets = append(targets, target)
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned request")
		}
		switch target {
		case "Logs_20140328.PutLogEvents":
			if !streamExists {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"__type":"ResourceNotFoundException","message":"The specified log stream does not exist."}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		case "Logs_20140328.CreateLogStream":
			streamExists = true
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected target %s", target)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	a, err := NewCloudWatchLogsAnchorer(CloudWatchLogsAnchorOptions{
		LogGroup:    "/taskgrant/anchor",
		Region:      "us-east-1",
		EndpointURL: srv.URL,
		Credentials: StaticCredentialsProvider{Credentials: AWSCredentials{
			AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret",
		}},
	})
	if err != nil {
		t.Fatalf("NewCloudWatchLogsAnchorer: %v", err)
	}
	cp := Checkpoint{Seq: 1, Hash: "abc", Timestamp: time.Now().UTC()}
	if err := a.Anchor(context.Background(), cp); err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	want := []string{
		"Logs_20140328.PutLogEvents",
		"Logs_20140328.CreateLogStream",
		"Logs_20140328.PutLogEvents",
	}
	if len(targets) != len(want) {
		t.Fatalf("call sequence %v, want %v", targets, want)
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("call %d: %s, want %s", i, targets[i], want[i])
		}
	}
}

func TestSignV4KnownVector(t *testing.T) {
	// The get-vanilla case of the AWS SigV4 test suite.
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	creds := AWSCredentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	when := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	emptyHash := SHA256Hex(nil)
	if err := SignV4(req, creds, "service", "us-east-1", emptyHash, when); err != nil {
		t.Fatalf("SignV4: %v", err)
	}
	const wantSig = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	auth := req.Header.Get("Authorization")
	if !strings.HasSuffix(auth, "Signature="+wantSig) {
		t.Fatalf("authorization %q lacks known-vector signature %s", auth, wantSig)
	}
	const wantAuth = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=" + wantSig
	if auth != wantAuth {
		t.Fatalf("authorization:\n got %s\nwant %s", auth, wantAuth)
	}
}
