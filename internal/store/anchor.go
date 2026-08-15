package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Checkpoint is one signed chain-head snapshot the broker writes to an
// external destination it can write but not delete or overwrite
// (section 9.3). A full-file rewrite of the log is detectable against
// the last checkpoint.
type Checkpoint struct {
	Seq         int64     `json:"seq"`
	Hash        string    `json:"hash"`
	RecordCount int64     `json:"record_count"`
	Timestamp   time.Time `json:"timestamp"`
	// Signature is the hex HMAC-SHA256 of the canonical JSON of the
	// checkpoint with Signature empty.
	Signature string `json:"signature,omitempty"`
}

// Anchorer writes one checkpoint to an external destination.
type Anchorer interface {
	Anchor(ctx context.Context, cp Checkpoint) error
}

// signCheckpoint computes the checkpoint HMAC.
func signCheckpoint(cp Checkpoint, key []byte) (string, error) {
	cp.Signature = ""
	body, err := CanonicalJSON(cp)
	if err != nil {
		return "", fmt.Errorf("store: checkpoint canonical form: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyCheckpoint reports whether the checkpoint signature is valid
// under key.
func VerifyCheckpoint(cp Checkpoint, key []byte) bool {
	want, err := signCheckpoint(cp, key)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(want), []byte(cp.Signature))
}

// Checkpoint captures and signs the current chain head. With zero
// records the head is the genesis hash.
func (s *Store) Checkpoint(hmacKey []byte) (Checkpoint, error) {
	if len(hmacKey) == 0 {
		return Checkpoint{}, errors.New("store: checkpoint requires an HMAC key")
	}
	s.writeMu.Lock()
	seq, hash := s.headSeq, s.headHash
	s.writeMu.Unlock()

	var count int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM records`).Scan(&count); err != nil {
		return Checkpoint{}, fmt.Errorf("store: checkpoint count: %w", err)
	}
	cp := Checkpoint{
		Seq:         seq,
		Hash:        hash,
		RecordCount: count,
		Timestamp:   time.Now().UTC(),
	}
	sig, err := signCheckpoint(cp, hmacKey)
	if err != nil {
		return Checkpoint{}, err
	}
	cp.Signature = sig
	return cp, nil
}

// StartAnchorLoop starts the store-owned anchor goroutine: one
// checkpoint immediately, then one per interval (default posture is
// hourly per section 9.3). Anchor failures are logged and retried on
// the next tick; they never stop the loop. The returned stop function
// blocks until the goroutine exits; Close calls it too.
func (s *Store) StartAnchorLoop(a Anchorer, interval time.Duration, hmacKey []byte) (stop func(), err error) {
	if a == nil {
		return nil, errors.New("store: anchor loop requires an anchorer")
	}
	if interval <= 0 {
		interval = time.Hour
	}
	if len(hmacKey) == 0 {
		return nil, errors.New("store: anchor loop requires an HMAC key")
	}
	s.anchorMu.Lock()
	defer s.anchorMu.Unlock()
	if s.anchorStop != nil {
		return nil, errors.New("store: anchor loop already running")
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	s.anchorStop, s.anchorDone = stopCh, doneCh

	go func() {
		defer close(doneCh)
		s.anchorOnce(a, hmacKey)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				s.anchorOnce(a, hmacKey)
			}
		}
	}()
	return func() { s.stopAnchorLoop() }, nil
}

func (s *Store) anchorOnce(a Anchorer, hmacKey []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cp, err := s.Checkpoint(hmacKey)
	if err != nil {
		s.logger.Error("store: checkpoint failed", "error", err)
		return
	}
	if err := a.Anchor(ctx, cp); err != nil {
		s.logger.Error("store: anchor write failed", "seq", cp.Seq, "error", err)
		return
	}
	s.logger.Info("store: anchored chain head", "seq", cp.Seq, "hash", cp.Hash)
}

func (s *Store) stopAnchorLoop() {
	s.anchorMu.Lock()
	stopCh, doneCh := s.anchorStop, s.anchorDone
	s.anchorStop, s.anchorDone = nil, nil
	s.anchorMu.Unlock()
	if stopCh == nil {
		return
	}
	close(stopCh)
	<-doneCh
}

// FileAnchorer appends checkpoints as JSON lines to a local file. It is
// the anchor implementation for tests and local sidecar use; it offers
// none of the delete protection of S3 Object Lock or CloudWatch Logs.
type FileAnchorer struct {
	path string
}

// NewFileAnchorer creates the parent directory and returns a file
// anchorer for path.
func NewFileAnchorer(path string) (*FileAnchorer, error) {
	if path == "" {
		return nil, errors.New("store: file anchorer requires a path")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: file anchorer dir: %w", err)
		}
	}
	return &FileAnchorer{path: path}, nil
}

// Anchor appends one checkpoint line.
func (f *FileAnchorer) Anchor(_ context.Context, cp Checkpoint) error {
	line, err := CanonicalJSON(cp)
	if err != nil {
		return err
	}
	fh, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("store: file anchor open: %w", err)
	}
	defer fh.Close()
	if _, err := fh.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("store: file anchor write: %w", err)
	}
	return nil
}
