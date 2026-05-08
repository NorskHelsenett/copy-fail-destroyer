package detector

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const dirtyFragModprobeConfPath = "/host/run/modprobe.d/disable-dirtyfrag.conf"
const dirtyFragModprobeRule = "install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n"

// UnloadDirtyFragModules attempts to unload esp4, esp6, and rxrpc kernel
// modules. Returns true if all target modules are no longer loaded.
func UnloadDirtyFragModules() (unloaded bool, detail string) {
	modules := []string{"esp4", "esp6", "rxrpc"}
	var results []string
	allOk := true

	for _, mod := range modules {
		err := unix.DeleteModule(mod, unix.O_NONBLOCK)
		if err == nil {
			results = append(results, mod+": unloaded")
		} else if err == unix.ENOENT {
			results = append(results, mod+": not loaded")
		} else {
			results = append(results, fmt.Sprintf("%s: failed (%v)", mod, err))
			allOk = false
		}
	}

	return allOk, strings.Join(results, "; ")
}

// BlacklistDirtyFragModules writes modprobe rules to prevent the kernel from
// auto-loading esp4, esp6, and rxrpc. The host filesystem must be mounted
// at /host.
func BlacklistDirtyFragModules() (applied bool, detail string) {
	existing, err := os.ReadFile(dirtyFragModprobeConfPath)
	if err == nil && string(existing) == dirtyFragModprobeRule {
		return true, "Dirty Frag modprobe blacklist already in place"
	}

	if err := os.WriteFile(dirtyFragModprobeConfPath, []byte(dirtyFragModprobeRule), 0644); err != nil {
		return false, fmt.Sprintf("failed to write Dirty Frag modprobe blacklist: %v", err)
	}

	return true, "Dirty Frag modprobe blacklist written to " + dirtyFragModprobeConfPath
}
