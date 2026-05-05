//go:build linux

package detector

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var debugLogging = os.Getenv("DEBUG") != ""

func debugLog(format string, args ...any) {
	if debugLogging {
		log.Printf("[debug] "+format, args...)
	}
}

func procComm(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}

// ScanAFALGAeadSockets returns the number of processes on the node that
// currently hold at least one AF_ALG socket open. It works by walking
// /proc/<pid>/fd for every visible process, duplicating each socket file
// descriptor into the current process via pidfd_getfd (Linux 5.6+), and
// calling getsockopt(SO_DOMAIN) to check the socket family.
//
// Note: the Linux kernel does not implement getsockname for AF_ALG sockets
// (alg_proto_ops uses sock_no_getname), so the algorithm type (aead vs hash
// vs skcipher) cannot be determined from the socket FD alone. All AF_ALG
// sockets are counted. The module refcount metric provides aead-specific
// confirmation that algif_aead is actually in use.
//
// Returns -1 when pidfd_getfd is not supported by the kernel (< 5.6) or when
// /proc cannot be read.
//
// Requirements:
//   - hostPID: true in the pod spec (so /proc exposes all host processes)
//   - privileged: true (provides CAP_SYS_PTRACE for cross-process fd dup)
func ScanAFALGAeadSockets() (count int, detail string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return -1, fmt.Sprintf("cannot read /proc: %v", err)
	}

	selfPID := os.Getpid()
	debugLog("scanning %d /proc entries (self pid %d)", len(entries), selfPID)

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == selfPID {
			continue
		}

		found, err := processHasAEADSocket(pid)
		if err != nil {
			if errors.Is(err, unix.ENOSYS) {
				return -1, "pidfd_getfd not supported on this kernel (requires Linux 5.6+)"
			}
			debugLog("pid %d (%s): scan error: %v", pid, procComm(pid), err)
			continue
		}
		if found {
			count++
		}
	}

	if count > 0 {
		return count, fmt.Sprintf("%d process(es) with active AF_ALG AEAD sockets", count)
	}
	return 0, "no processes with active AF_ALG AEAD sockets found"
}

// processHasAEADSocket returns true if pid has at least one AF_ALG AEAD socket
// open. It opens a pidfd once and reuses it across all fds for efficiency, and
// returns as soon as the first matching socket is found.
func processHasAEADSocket(pid int) (bool, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return false, err // process may have exited
	}

	comm := procComm(pid)

	// Open a pidfd once for the whole process; reused for every PidfdGetfd call.
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		debugLog("pid %d (%s): pidfd_open: %v", pid, comm, err)
		return false, err // process exited between ReadDir and here
	}
	defer unix.Close(pidfd)

	for _, e := range entries {
		fdNum, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		// Cheap filter: skip non-socket fds without a syscall.
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}

		dupFd, err := unix.PidfdGetfd(pidfd, fdNum, 0)
		if err != nil {
			if errors.Is(err, unix.ENOSYS) {
				return false, unix.ENOSYS // propagate: kernel too old
			}
			debugLog("pid %d (%s) fd %s: pidfd_getfd: %v", pid, comm, e.Name(), err)
			continue
		}

		// getsockname is not implemented for AF_ALG sockets (sock_no_getname in
		// alg_proto_ops), so use SO_DOMAIN to read the socket family instead.
		family, soErr := unix.GetsockoptInt(dupFd, unix.SOL_SOCKET, unix.SO_DOMAIN)
		unix.Close(dupFd)

		if soErr != nil {
			debugLog("pid %d (%s) fd %s: SO_DOMAIN: %v", pid, comm, e.Name(), soErr)
			continue
		}

		if family != unix.AF_ALG {
			continue
		}

		debugLog("pid %d (%s) fd %s: MATCH — AF_ALG socket (family %d)", pid, comm, e.Name(), family)
		return true, nil // early exit: no need to inspect remaining fds
	}

	return false, nil
}
