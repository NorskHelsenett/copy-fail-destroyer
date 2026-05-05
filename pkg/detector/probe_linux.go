package detector

import (
	"fmt"
	"log"

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

// HoldAFALGSocket opens and binds an AF_ALG AEAD socket and blocks forever,
// keeping the file descriptor open. Used by the hold-afalg subcommand to
// provide a live target for the per-process socket scan.
func HoldAFALGSocket() error {
	fd, err := unix.Socket(38, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return fmt.Errorf("AF_ALG socket: %w", err)
	}
	addr := &unix.SockaddrALG{
		Type: "aead",
		Name: "authenc(hmac(sha256),cbc(aes))",
	}
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return fmt.Errorf("AF_ALG bind: %w", err)
	}
	log.Println("AF_ALG AEAD socket open and bound — holding for test")
	select {} // block forever; fd stays open
}
