package detector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ProbeESP checks whether the esp4 or esp6 kernel modules are loaded or
// available on disk (autoloadable). Does not trigger module loading.
func ProbeESP() (reachable bool, detail string) {
	esp4Loaded := isModuleLoaded("esp4")
	esp6Loaded := isModuleLoaded("esp6")

	if esp4Loaded || esp6Loaded {
		var loaded []string
		if esp4Loaded {
			loaded = append(loaded, "esp4")
		}
		if esp6Loaded {
			loaded = append(loaded, "esp6")
		}
		return true, fmt.Sprintf("ESP module(s) loaded: %s", strings.Join(loaded, ", "))
	}

	esp4OnDisk := isModuleOnDisk("esp4", "kernel/net/ipv4/esp4.ko")
	esp6OnDisk := isModuleOnDisk("esp6", "kernel/net/ipv6/esp6.ko")

	if esp4OnDisk || esp6OnDisk {
		var avail []string
		if esp4OnDisk {
			avail = append(avail, "esp4")
		}
		if esp6OnDisk {
			avail = append(avail, "esp6")
		}
		return true, fmt.Sprintf("ESP module(s) not loaded but available on disk (autoloadable): %s", strings.Join(avail, ", "))
	}

	return false, "ESP modules (esp4, esp6) not loaded and not found on disk"
}

// ProbeRxRPC checks whether the rxrpc kernel module is loaded or available
// on disk. Does NOT create a socket (which would autoload the module).
func ProbeRxRPC() (reachable bool, detail string) {
	if isModuleLoaded("rxrpc") {
		return true, "rxrpc module is loaded"
	}

	if isModuleOnDisk("rxrpc", "kernel/net/rxrpc/rxrpc.ko") ||
		isModuleOnDisk("af-rxrpc", "kernel/net/rxrpc/af-rxrpc.ko") {
		return true, "rxrpc module not loaded but available on disk (autoloadable)"
	}

	return false, "rxrpc module not loaded and not found on disk"
}

// ProbeUserNS checks whether unprivileged user namespace creation is available.
// This is relevant for the ESP variant which requires CLONE_NEWUSER.
func ProbeUserNS() (available bool, detail string) {
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		val := strings.TrimSpace(string(data))
		if val == "0" {
			return false, "unprivileged user namespaces disabled via kernel.unprivileged_userns_clone=0"
		}
	}

	if data, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		val := strings.TrimSpace(string(data))
		if val == "0" {
			return false, "unprivileged user namespaces disabled via user.max_user_namespaces=0"
		}
	}

	return true, "unprivileged user namespace creation appears available"
}

// ProbeDirtyFragMitigation checks whether modprobe blacklist rules are in
// place for the Dirty Frag modules.
func ProbeDirtyFragMitigation() (mitigated bool, detail string) {
	targets := []string{"esp4", "esp6", "rxrpc"}
	var blocked, notBlocked []string

	for _, mod := range targets {
		if isModuleBlacklisted(mod) {
			blocked = append(blocked, mod)
		} else {
			notBlocked = append(notBlocked, mod)
		}
	}

	if len(notBlocked) == 0 {
		return true, fmt.Sprintf("all Dirty Frag modules blacklisted: %s", strings.Join(blocked, ", "))
	}
	if len(blocked) > 0 {
		return false, fmt.Sprintf("partially mitigated — blacklisted: %s; not blacklisted: %s",
			strings.Join(blocked, ", "), strings.Join(notBlocked, ", "))
	}
	return false, "no Dirty Frag modules are blacklisted"
}

func isModuleLoaded(name string) bool {
	_, err := os.Stat("/sys/module/" + name)
	return err == nil
}

func isModuleOnDisk(name, relPath string) bool {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false
	}
	release := strings.TrimRight(string(uts.Release[:]), "\x00")

	for _, prefix := range []string{"", "/host"} {
		base := filepath.Join(prefix, "lib", "modules", release)
		for _, ext := range []string{"", ".zst", ".xz", ".gz", ".lz4"} {
			path := filepath.Join(base, relPath+ext)
			if _, err := os.Stat(path); err == nil {
				return true
			}
		}
	}
	return false
}

func isModuleBlacklisted(name string) bool {
	rule := fmt.Sprintf("install %s /bin/false", name)

	for _, dir := range []string{
		"/etc/modprobe.d",
		"/host/etc/modprobe.d",
		"/host/run/modprobe.d",
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			if strings.Contains(string(data), rule) {
				return true
			}
		}
	}
	return false
}
