package detector

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// ProbeAFALG tests whether the AF_ALG socket interface and the specific
// algorithm used by CVE-2022-27666 are reachable. This is safe — it only
// creates a socket, attempts a bind, and closes it immediately.
func ProbeAFALG() (reachable bool, detail string) {
	// AF_ALG = 38, SOCK_SEQPACKET = 5
	fd, err := unix.Socket(38, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return false, fmt.Sprintf("AF_ALG socket not available: %v", err)
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrALG{
		Type: "aead",
		Name: "authenc(hmac(sha256),cbc(aes))",
	}
	if err := unix.Bind(fd, addr); err != nil {
		return false, fmt.Sprintf("AF_ALG bind failed (algorithm not available): %v", err)
	}

	return true, "AF_ALG aead authenc(hmac(sha256),cbc(aes)) is reachable"
}
