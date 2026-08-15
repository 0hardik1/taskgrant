//go:build darwin

package adminapi

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredential reads LOCAL_PEERCRED (uid and groups) and
// LOCAL_PEERPID (pid) of the process that connected to the unix
// socket, the darwin equivalent of SO_PEERCRED.
func peerCredential(uc *net.UnixConn) (PeerCred, error) {
	var cred PeerCred
	err := controlRawConn(uc, func(fd uintptr) error {
		xucred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			return fmt.Errorf("adminapi: LOCAL_PEERCRED: %w", err)
		}
		cred.UID = int(xucred.Uid)
		if xucred.Ngroups > 0 {
			cred.GID = int(xucred.Groups[0])
		}
		if pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
			cred.PID = pid
		}
		return nil
	})
	return cred, err
}
