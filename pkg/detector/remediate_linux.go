package detector

import (
	"fmt"

	"golang.org/x/sys/unix"
)

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
