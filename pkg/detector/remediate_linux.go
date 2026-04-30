package detector

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const modprobeConfPath = "/host/run/modprobe.d/disable-algif-aead.conf"
const modprobeRule = "install algif_aead /bin/false\n"

// UnloadAFALGModule attempts to unload the algif_aead kernel module, which
// provides the attack surface for CVE-2022-27666. Requires CAP_SYS_MODULE.
// Returns true if the module was successfully unloaded or was not loaded.
func UnloadAFALGModule() (unloaded bool, detail string) {
	// O_NONBLOCK makes delete_module return immediately rather than waiting
	// for the module reference count to drop.
	err := unix.DeleteModule("algif_aead", unix.O_NONBLOCK)
	if err == nil {
		return true, "algif_aead module unloaded successfully"
	}

	// ENOENT means the module is not loaded — that's fine.
	if err == unix.ENOENT {
		return true, "algif_aead module is not loaded"
	}

	return false, fmt.Sprintf("failed to unload algif_aead: %v", err)
}

// BlacklistAFALGModule writes a modprobe rule to prevent the kernel from
// auto-loading algif_aead. The host's /etc must be mounted at /host/etc.
// Returns true if the blacklist is already in place or was written successfully.
func BlacklistAFALGModule() (applied bool, detail string) {
	// Check if already in place.
	existing, err := os.ReadFile(modprobeConfPath)
	if err == nil && string(existing) == modprobeRule {
		return true, "modprobe blacklist already in place"
	}

	if err := os.WriteFile(modprobeConfPath, []byte(modprobeRule), 0644); err != nil {
		return false, fmt.Sprintf("failed to write modprobe blacklist: %v", err)
	}

	return true, "modprobe blacklist written to " + modprobeConfPath
}
