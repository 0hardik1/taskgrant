//go:build !linux && !darwin

package adminapi

import (
	"errors"
	"net"
)

// peerCredential is unavailable on this platform; unix socket
// connections carry no approver identity, so approve and deny fail
// closed with 401 while read-only endpoints keep working.
func peerCredential(*net.UnixConn) (PeerCred, error) {
	return PeerCred{}, errors.New("adminapi: peer credentials unsupported on this platform")
}
