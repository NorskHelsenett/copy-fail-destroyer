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
// currently hold at least one AF_ALG AEAD socket open. It works by walking
// /proc/<pid>/fd for every visible process, duplicating each socket file
// descriptor into the current process via pidfd_getfd (Linux 5.6+), and
// calling getsockname to inspect the bound algorithm type.
//
// This approach works whether algif_aead is a loadable module or compiled
// into the kernel as a built-in.
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

		sa, gsErr := unix.Getsockname(dupFd)
		unix.Close(dupFd)

		if gsErr != nil {
			debugLog("pid %d (%s) fd %s: getsockname: %v", pid, comm, e.Name(), gsErr)
			continue
		}

		alg, ok := sa.(*unix.SockaddrALG)
		if !ok {
			continue // not AF_ALG — expected for most sockets
		}

		debugLog("pid %d (%s) fd %s: AF_ALG socket type=%q name=%q", pid, comm, e.Name(), alg.Type, alg.Name)

		if alg.Type == "aead" {
			debugLog("pid %d (%s) fd %s: MATCH — AF_ALG AEAD socket", pid, comm, e.Name())
			return true, nil // early exit: no need to inspect remaining fds
		}
	}

	return false, nil
}
