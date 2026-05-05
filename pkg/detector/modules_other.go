// This file is only compiled on non-Linux platforms where AF_ALG is not available.

//go:build !linux

package detector

// AFALGAeadModuleRefcount is a no-op on non-Linux platforms.
func AFALGAeadModuleRefcount() (refcount int, detail string) {
	return -1, "AF_ALG is only available on Linux"
}
