package detector

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// CVE-2026-31431 "Copy Fail" — algif_aead in-place logic flaw allowing
// page-cache writes from unprivileged userspace. Introduced in kernel 4.14
// (commit 72548b093ee3), fixed in 6.18.22, 6.19.12, and 7.0.
//
// Affected: 4.14 <= kernel < 6.18.22, and 6.19.0 <= kernel < 6.19.12
// Unaffected: < 4.14, >= 6.18.22 (on 6.18.x), >= 6.19.12 (on 6.19.x), >= 7.0

// IsVulnerableCVE202631431 checks whether the running kernel is vulnerable to
// CVE-2026-31431 and whether the AF_ALG module is reachable.
func IsVulnerableCVE202631431() (vulnerable bool, reason string, err error) {
	needsPatching, detail, err := KernelNeedsPatchingCVE202631431()
	if err != nil {
		return false, "", err
	}

	moduleReachable, moduleMsg := ProbeAFALG()
	combined := detail + "; " + moduleMsg

	if needsPatching && moduleReachable {
		return true, "VULNERABLE: " + combined, nil
	}
	if needsPatching && !moduleReachable {
		return false, "kernel version is vulnerable but module is not reachable (exploit blocked): " + combined, nil
	}
	return false, "not vulnerable: " + combined, nil
}

// KernelNeedsPatchingCVE202631431 checks only the kernel version against the
// known fixed versions for CVE-2026-31431.
func KernelNeedsPatchingCVE202631431() (needsPatching bool, detail string, err error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false, "", fmt.Errorf("uname: %w", err)
	}

	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	major, minor, patch, err := parseKernelVersion(release)
	if err != nil {
		return false, "", fmt.Errorf("parsing kernel version %q: %w", release, err)
	}

	vuln, msg := checkCVE202631431(major, minor, patch, release)
	return vuln, msg, nil
}

func checkCVE202631431(major, minor, patch int, release string) (vulnerable bool, detail string) {
	// Before 4.14: not affected (bug was introduced in 4.14).
	if major < 4 || (major == 4 && minor < 14) {
		return false, fmt.Sprintf("kernel %s predates the vulnerable commit (introduced in 4.14)", release)
	}

	// 7.0+: fixed in mainline.
	if major >= 7 {
		return false, fmt.Sprintf("kernel %s is >= 7.0 (fixed in mainline)", release)
	}

	// 6.19.x: fixed in 6.19.12.
	if major == 6 && minor == 19 {
		if patch >= 12 {
			return false, fmt.Sprintf("kernel %s is patched (need >= 6.19.12)", release)
		}
		return true, fmt.Sprintf("kernel %s needs patching (fix in 6.19.12)", release)
	}

	// 6.18.x: fixed in 6.18.22.
	if major == 6 && minor == 18 {
		if patch >= 22 {
			return false, fmt.Sprintf("kernel %s is patched (need >= 6.18.22)", release)
		}
		return true, fmt.Sprintf("kernel %s needs patching (fix in 6.18.22)", release)
	}

	// Anything else between 4.14 and 6.18/6.19/7.0 — no stable backport
	// available, so the kernel is vulnerable.
	return true, fmt.Sprintf("kernel %s is in the affected range (4.14 – 6.18.21 / 6.19.11) with no backport available", release)
}

// parseKernelVersion extracts major.minor.patch from a release string like
// "5.15.28-generic".
func parseKernelVersion(release string) (major, minor, patch int, err error) {
	// Strip everything after the first non-version character.
	ver := release
	for i, c := range release {
		if c != '.' && (c < '0' || c > '9') {
			ver = release[:i]
			break
		}
	}

	parts := strings.SplitN(ver, ".", 4)
	if len(parts) < 3 {
		return 0, 0, 0, fmt.Errorf("expected at least major.minor.patch, got %q", ver)
	}

	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return
	}
	patch, err = strconv.Atoi(parts[2])
	return
}
