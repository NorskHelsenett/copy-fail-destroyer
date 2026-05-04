//go:build linux

package detector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// AFALGAeadModuleRefcount returns the reference count of the algif_aead kernel
// module from /proc/modules. A value > 0 means at least one process currently
// holds an AF_ALG AEAD socket open. Returns -1 if the module is not loaded or
// /proc/modules cannot be read.
func AFALGAeadModuleRefcount() (refcount int, detail string) {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return -1, fmt.Sprintf("cannot read /proc/modules: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[0] != "algif_aead" {
			continue
		}
		n, err := strconv.Atoi(fields[2])
		if err != nil {
			return -1, fmt.Sprintf("cannot parse algif_aead refcount: %v", err)
		}
		if n > 0 {
			return n, fmt.Sprintf("algif_aead is actively used (refcount=%d)", n)
		}
		return 0, "algif_aead loaded but not in active use (refcount=0)"
	}
	return -1, "algif_aead module not loaded"
}
