// This file is only compiled on non-Linux platforms where AF_ALG is not available.

//go:build !linux

package detector

import "fmt"

// ProbeAFALG is a no-op on non-Linux platforms.
func ProbeAFALG() (reachable bool, detail string) {
	return false, "AF_ALG is only available on Linux"
}

// HoldAFALGSocket is a no-op on non-Linux platforms.
func HoldAFALGSocket() error {
	return fmt.Errorf("not supported on this platform")
}
