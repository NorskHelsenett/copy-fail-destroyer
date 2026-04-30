// This file is only compiled on non-Linux platforms where AF_ALG is not available.

//go:build !linux

package detector

// ProbeAFALG is a no-op on non-Linux platforms.
func ProbeAFALG() (reachable bool, detail string) {
	return false, "AF_ALG is only available on Linux"
}
