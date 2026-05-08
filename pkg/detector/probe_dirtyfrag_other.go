//go:build !linux

package detector

// ProbeESP is a no-op on non-Linux platforms.
func ProbeESP() (reachable bool, detail string) {
	return false, "ESP modules are only available on Linux"
}

// ProbeRxRPC is a no-op on non-Linux platforms.
func ProbeRxRPC() (reachable bool, detail string) {
	return false, "rxrpc module is only available on Linux"
}

// ProbeUserNS is a no-op on non-Linux platforms.
func ProbeUserNS() (available bool, detail string) {
	return false, "user namespace check is only available on Linux"
}

// ProbeDirtyFragMitigation is a no-op on non-Linux platforms.
func ProbeDirtyFragMitigation() (mitigated bool, detail string) {
	return false, "Dirty Frag mitigation check is only supported on Linux"
}
