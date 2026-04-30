//go:build !linux

package detector

// UnloadAFALGModule is a no-op on non-Linux platforms.
func UnloadAFALGModule() (unloaded bool, detail string) {
	return false, "module unloading is only supported on Linux"
}
