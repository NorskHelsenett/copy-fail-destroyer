package detector

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// patchedVersions lists the minimum patched kernel version for each maintained
// branch at the time CVE-2022-27666 was fixed (ESP6 / AF_ALG heap overflow).
var patchedVersions = []kernelRange{
	{major: 5, minor: 17, patch: 0}, // mainline fix
	{major: 5, minor: 16, patch: 15},
	{major: 5, minor: 15, patch: 29},
	{major: 5, minor: 10, patch: 106},
	{major: 5, minor: 4, patch: 185},
	{major: 4, minor: 19, patch: 235},
	{major: 4, minor: 14, patch: 272},
	{major: 4, minor: 9, patch: 307},
}

type kernelRange struct {
	major, minor, patch int
}

// IsVulnerableCVE202227666 returns true if the running kernel is vulnerable to
// CVE-2022-27666 based on its version string and whether the AF_ALG module is
// reachable. It also returns a human-readable reason string.
func IsVulnerableCVE202227666() (vulnerable bool, reason string, err error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false, "", fmt.Errorf("uname: %w", err)
	}

	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	major, minor, patch, err := parseKernelVersion(release)
	if err != nil {
		return false, "", fmt.Errorf("parsing kernel version %q: %w", release, err)
	}

	versionVuln := false
	versionMsg := ""

	// Find the matching stable branch and check if the patch level is sufficient.
	matched := false
	for _, pv := range patchedVersions {
		if major == pv.major && minor == pv.minor {
			matched = true
			if patch >= pv.patch {
				versionMsg = fmt.Sprintf("kernel %s is patched (need >= %d.%d.%d)", release, pv.major, pv.minor, pv.patch)
			} else {
				versionVuln = true
				versionMsg = fmt.Sprintf("kernel %s is vulnerable (patched in %d.%d.%d)", release, pv.major, pv.minor, pv.patch)
			}
			break
		}
		// If major.minor is higher than the mainline fix, it's patched.
		if major > pv.major || (major == pv.major && minor > pv.minor) {
			matched = true
			versionMsg = fmt.Sprintf("kernel %s is newer than the fix", release)
			break
		}
	}
	if !matched {
		versionVuln = true
		versionMsg = fmt.Sprintf("kernel %s is older than all tracked patched branches", release)
	}

	// Probe whether the AF_ALG module and algorithm are reachable.
	moduleReachable, moduleMsg := ProbeAFALG()

	combined := versionMsg + "; " + moduleMsg

	if versionVuln && moduleReachable {
		return true, "VULNERABLE: " + combined, nil
	}
	if versionVuln && !moduleReachable {
		return false, "kernel version is vulnerable but module is not reachable (exploit blocked): " + combined, nil
	}
	return false, "not vulnerable: " + combined, nil
}

// KernelNeedsPatching returns true if the running kernel version is not patched
// for CVE-2022-27666, regardless of whether the AF_ALG module is loaded.
func KernelNeedsPatching() (needsPatching bool, detail string, err error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false, "", fmt.Errorf("uname: %w", err)
	}

	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	major, minor, patch, err := parseKernelVersion(release)
	if err != nil {
		return false, "", fmt.Errorf("parsing kernel version %q: %w", release, err)
	}

	for _, pv := range patchedVersions {
		if major == pv.major && minor == pv.minor {
			if patch >= pv.patch {
				return false, fmt.Sprintf("kernel %s is patched (need >= %d.%d.%d)", release, pv.major, pv.minor, pv.patch), nil
			}
			return true, fmt.Sprintf("kernel %s needs patching (fix in %d.%d.%d)", release, pv.major, pv.minor, pv.patch), nil
		}
		if major > pv.major || (major == pv.major && minor > pv.minor) {
			return false, fmt.Sprintf("kernel %s is newer than the fix", release), nil
		}
	}

	return true, fmt.Sprintf("kernel %s is older than all tracked patched branches", release), nil
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
