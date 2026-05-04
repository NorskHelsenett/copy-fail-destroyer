// This file is only compiled on non-Linux platforms where AF_ALG is not available.

//go:build !linux

package detector

// ScanAFALGAeadSockets is a no-op on non-Linux platforms.
func ScanAFALGAeadSockets() (count int, detail string) {
	return -1, "AF_ALG socket scanning is only available on Linux"
}
