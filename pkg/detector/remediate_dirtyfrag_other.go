//go:build !linux

package detector

// UnloadDirtyFragModules is a no-op on non-Linux platforms.
func UnloadDirtyFragModules() (unloaded bool, detail string) {
	return false, "module unloading is only supported on Linux"
}

// BlacklistDirtyFragModules is a no-op on non-Linux platforms.
func BlacklistDirtyFragModules() (applied bool, detail string) {
	return false, "modprobe blacklist is only supported on Linux"
}
