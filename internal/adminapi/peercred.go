package adminapi

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"strconv"
)

// PeerCred is the OS identity on the far end of a unix socket
// connection, the approver identity for the CLI path (section 11).
type PeerCred struct {
	UID int
	GID int
	PID int
}

// Principal resolves the peer uid to a username, falling back to
// "uid:<n>" when the lookup fails (for example inside a minimal
// container without a passwd file).
func (p PeerCred) Principal() string {
	if u, err := user.LookupId(strconv.Itoa(p.UID)); err == nil && u.Username != "" {
		return u.Username
	}
	return "uid:" + strconv.Itoa(p.UID)
}

// peerCredKey carries the PeerCred through the request context from
// the listener's ConnContext hook to the handlers.
type peerCredKey struct{}

// unixConnContext is an http.Server.ConnContext hook that captures the
// unix peer credentials at accept time.
func unixConnContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	cred, err := peerCredential(uc)
	if err != nil {
		// No credential means no approver identity for this
		// connection; read-only endpoints still work.
		return ctx
	}
	return context.WithValue(ctx, peerCredKey{}, cred)
}

// peerCredFromContext returns the peer credential captured at accept
// time, if any.
func peerCredFromContext(ctx context.Context) (PeerCred, bool) {
	cred, ok := ctx.Value(peerCredKey{}).(PeerCred)
	return cred, ok
}

// controlRawConn runs f over the connection's raw file descriptor.
func controlRawConn(uc *net.UnixConn, f func(fd uintptr) error) error {
	raw, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("adminapi: raw conn: %w", err)
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) { opErr = f(fd) }); err != nil {
		return fmt.Errorf("adminapi: conn control: %w", err)
	}
	return opErr
}
