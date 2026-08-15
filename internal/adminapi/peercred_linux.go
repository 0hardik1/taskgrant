//go:build linux

package adminapi

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredential reads SO_PEERCRED: the uid, gid, and pid of the
// process that connected to the unix socket.
func peerCredential(uc *net.UnixConn) (PeerCred, error) {
	var cred PeerCred
	err := controlRawConn(uc, func(fd uintptr) error {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return fmt.Errorf("adminapi: SO_PEERCRED: %w", err)
		}
		cred = PeerCred{UID: int(ucred.Uid), GID: int(ucred.Gid), PID: int(ucred.Pid)}
		return nil
	})
	return cred, err
}
