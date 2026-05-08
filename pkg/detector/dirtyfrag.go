package detector

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// Dirty Frag — two chained page-cache write vulnerabilities allowing
// unprivileged root escalation on most Linux distributions.
//
// 1. xfrm-ESP Page-Cache Write: esp_input() bypasses skb_cow_data() for
//    non-linear skbs with shared frags, allowing in-place crypto on
//    attacker-pinned page-cache pages. Introduced in 4.10 (cac2661c53f3,
//    2017-01-17). Requires esp4/esp6 module + user namespace privileges.
//
// 2. RxRPC Page-Cache Write: rxkad_verify_packet_1() performs in-place
//    pcbc(fcrypt) decrypt on page-cache frags. Introduced in 6.4
//    (2dc334f1a63a, 2023-06). Requires rxrpc module but NO namespace
//    privileges.
//
// Reference: https://github.com/V4bel/dirtyfrag

// IsVulnerableDirtyFrag checks whether the running system is exploitable
// via either Dirty Frag variant.
func IsVulnerableDirtyFrag() (vulnerable bool, reason string, err error) {
	espVuln, espReason, espErr := IsVulnerableDirtyFragESP()
	if espErr != nil {
		return false, "", espErr
	}
	rxrpcVuln, rxrpcReason, rxrpcErr := IsVulnerableDirtyFragRxRPC()
	if rxrpcErr != nil {
		return false, "", rxrpcErr
	}

	combined := "ESP: " + espReason + "; RxRPC: " + rxrpcReason
	if espVuln || rxrpcVuln {
		return true, "VULNERABLE: " + combined, nil
	}
	return false, "not vulnerable: " + combined, nil
}

// IsVulnerableDirtyFragESP checks the ESP variant specifically.
func IsVulnerableDirtyFragESP() (vulnerable bool, reason string, err error) {
	needsPatch, detail, err := KernelNeedsPatchingDirtyFragESP()
	if err != nil {
		return false, "", err
	}

	espReachable, espMsg := ProbeESP()
	combined := detail + "; " + espMsg

	if needsPatch && espReachable {
		return true, "VULNERABLE (ESP): " + combined, nil
	}
	if needsPatch && !espReachable {
		return false, "kernel vulnerable but ESP modules not reachable: " + combined, nil
	}
	return false, "not vulnerable (ESP): " + combined, nil
}

// IsVulnerableDirtyFragRxRPC checks the RxRPC variant specifically.
func IsVulnerableDirtyFragRxRPC() (vulnerable bool, reason string, err error) {
	needsPatch, detail, err := KernelNeedsPatchingDirtyFragRxRPC()
	if err != nil {
		return false, "", err
	}

	rxrpcReachable, rxrpcMsg := ProbeRxRPC()
	combined := detail + "; " + rxrpcMsg

	if needsPatch && rxrpcReachable {
		return true, "VULNERABLE (RxRPC): " + combined, nil
	}
	if needsPatch && !rxrpcReachable {
		return false, "kernel vulnerable but rxrpc module not reachable: " + combined, nil
	}
	return false, "not vulnerable (RxRPC): " + combined, nil
}

// KernelNeedsPatchingDirtyFragESP checks only the kernel version against the
// known affected range for the ESP variant.
func KernelNeedsPatchingDirtyFragESP() (needsPatching bool, detail string, err error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false, "", fmt.Errorf("uname: %w", err)
	}

	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	major, minor, patch, err := parseKernelVersion(release)
	if err != nil {
		return false, "", fmt.Errorf("parsing kernel version %q: %w", release, err)
	}

	vuln, msg := checkDirtyFragESP(major, minor, patch, release)
	return vuln, msg, nil
}

// KernelNeedsPatchingDirtyFragRxRPC checks only the kernel version against the
// known affected range for the RxRPC variant.
func KernelNeedsPatchingDirtyFragRxRPC() (needsPatching bool, detail string, err error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false, "", fmt.Errorf("uname: %w", err)
	}

	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	major, minor, patch, err := parseKernelVersion(release)
	if err != nil {
		return false, "", fmt.Errorf("parsing kernel version %q: %w", release, err)
	}

	vuln, msg := checkDirtyFragRxRPC(major, minor, patch, release)
	return vuln, msg, nil
}

// KernelNeedsPatchingDirtyFrag returns true if the kernel version is in the
// affected range for either Dirty Frag variant.
func KernelNeedsPatchingDirtyFrag() (needsPatching bool, detail string, err error) {
	espNeeds, espDetail, err := KernelNeedsPatchingDirtyFragESP()
	if err != nil {
		return false, "", err
	}
	rxrpcNeeds, rxrpcDetail, err := KernelNeedsPatchingDirtyFragRxRPC()
	if err != nil {
		return false, "", err
	}

	combined := "ESP: " + espDetail + "; RxRPC: " + rxrpcDetail
	return espNeeds || rxrpcNeeds, combined, nil
}

func checkDirtyFragESP(major, minor, patch int, release string) (vulnerable bool, detail string) {
	// Before 4.10: not affected (introduced in cac2661c53f3, first in 4.10).
	if major < 4 || (major == 4 && minor < 10) {
		return false, fmt.Sprintf("kernel %s predates the ESP vulnerability (introduced in 4.10)", release)
	}

	// Patch merged into netdev tree 2026-05-07 (f4c50a4034e6).
	// No stable release contains the fix yet.
	// TODO: update these ranges when distros backport the patch.

	return true, fmt.Sprintf("kernel %s is in the ESP-affected range (>= 4.10, no stable fix available yet)", release)
}

func checkDirtyFragRxRPC(major, minor, patch int, release string) (vulnerable bool, detail string) {
	// Before 6.4: not affected (introduced in 2dc334f1a63a, first in 6.4).
	if major < 6 || (major == 6 && minor < 4) {
		return false, fmt.Sprintf("kernel %s predates the RxRPC vulnerability (introduced in 6.4)", release)
	}

	// Patch submitted but NOT merged upstream as of 2026-05-08.
	// TODO: update these ranges when the patch is merged and backported.

	return true, fmt.Sprintf("kernel %s is in the RxRPC-affected range (>= 6.4, no fix available yet)", release)
}
