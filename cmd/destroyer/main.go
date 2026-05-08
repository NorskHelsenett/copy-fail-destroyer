package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NorskHelsenett/copy-fail-destroyer/pkg/detector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// CVE-2026-31431 "Copy Fail"
	copyFailVulnerable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cve_2026_31431_vulnerable",
		Help: "1 if the kernel is vulnerable to CVE-2026-31431 (Copy Fail) and module is reachable, 0 otherwise.",
	})
	copyFailNeedsPatching = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cve_2026_31431_kernel_needs_patching",
		Help: "1 if the kernel version is not patched for CVE-2026-31431, 0 otherwise.",
	})
	moduleReachable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cve_2026_31431_module_reachable",
		Help: "1 if the AF_ALG module and algorithm are reachable, 0 otherwise.",
	})
	remediationApplied = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cve_2026_31431_remediation_applied",
		Help: "1 if the algif_aead module was successfully unloaded, 0 otherwise.",
	})

	// Dirty Frag
	dirtyFragVulnerable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dirty_frag_vulnerable",
		Help: "1 if the kernel is vulnerable to Dirty Frag (ESP or RxRPC variant) and modules are reachable, 0 otherwise.",
	})
	dirtyFragKernelNeedsPatching = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dirty_frag_kernel_needs_patching",
		Help: "1 if the kernel version is not patched for Dirty Frag (either variant), 0 otherwise.",
	})
	dirtyFragESPReachable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dirty_frag_esp_module_reachable",
		Help: "1 if the esp4 or esp6 kernel module is loaded or available on disk, 0 otherwise.",
	})
	dirtyFragRxRPCReachable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dirty_frag_rxrpc_module_reachable",
		Help: "1 if the rxrpc kernel module is loaded or available on disk, 0 otherwise.",
	})
	dirtyFragRemediationApplied = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dirty_frag_remediation_applied",
		Help: "1 if the Dirty Frag module mitigations have been applied, 0 otherwise.",
	})
)

func init() {
	prometheus.MustRegister(copyFailVulnerable)
	prometheus.MustRegister(copyFailNeedsPatching)
	prometheus.MustRegister(moduleReachable)
	prometheus.MustRegister(remediationApplied)
	prometheus.MustRegister(dirtyFragVulnerable)
	prometheus.MustRegister(dirtyFragKernelNeedsPatching)
	prometheus.MustRegister(dirtyFragESPReachable)
	prometheus.MustRegister(dirtyFragRxRPCReachable)
	prometheus.MustRegister(dirtyFragRemediationApplied)
}

func check() {
	// --- CVE-2026-31431 (Copy Fail) ---
	cfVuln, cfReason, cfErr := detector.IsVulnerableCVE202631431()
	if cfErr != nil {
		log.Printf("CVE-2026-31431 check error: %v", cfErr)
	} else {
		log.Printf("CVE-2026-31431 check: %s", cfReason)
		if cfVuln {
			copyFailVulnerable.Set(1)
		} else {
			copyFailVulnerable.Set(0)
		}
	}

	cfNeedsPatch, cfPatchDetail, cfPatchErr := detector.KernelNeedsPatchingCVE202631431()
	if cfPatchErr != nil {
		log.Printf("CVE-2026-31431 patch check error: %v", cfPatchErr)
	} else {
		log.Printf("CVE-2026-31431 patch check: %s", cfPatchDetail)
		if cfNeedsPatch {
			copyFailNeedsPatching.Set(1)
		} else {
			copyFailNeedsPatching.Set(0)
		}
	}

	reachable, probeDetail := detector.ProbeAFALG()
	if reachable {
		moduleReachable.Set(1)
	} else {
		moduleReachable.Set(0)
	}

	// Remediate Copy Fail: if the module is reachable, act based on REMEDIATION_MODE.
	if reachable {
		mode := strings.ToLower(strings.TrimSpace(os.Getenv("REMEDIATION_MODE")))
		if mode == "" {
			mode = "unload"
		}

		switch mode {
		case "disabled":
			log.Printf("module reachable (%s), remediation disabled by REMEDIATION_MODE", probeDetail)
		case "unload":
			log.Printf("module reachable (%s), attempting unload", probeDetail)
			unloaded, detail := detector.UnloadAFALGModule()
			log.Printf("remediation: %s", detail)
			if unloaded {
				remediationApplied.Set(1)
				moduleReachable.Set(0)
			} else {
				remediationApplied.Set(0)
			}
		case "blacklist":
			log.Printf("module reachable (%s), attempting unload + blacklist", probeDetail)
			unloaded, detail := detector.UnloadAFALGModule()
			log.Printf("remediation (unload): %s", detail)
			if unloaded {
				remediationApplied.Set(1)
				moduleReachable.Set(0)
			} else {
				remediationApplied.Set(0)
			}
			applied, blDetail := detector.BlacklistAFALGModule()
			log.Printf("remediation (blacklist): %s", blDetail)
			if !applied {
				remediationApplied.Set(0)
			}
		default:
			log.Printf("unknown REMEDIATION_MODE %q, skipping remediation", mode)
		}
	}

	// --- Dirty Frag ---
	dfVuln, dfReason, dfErr := detector.IsVulnerableDirtyFrag()
	if dfErr != nil {
		log.Printf("Dirty Frag check error: %v", dfErr)
	} else {
		log.Printf("Dirty Frag check: %s", dfReason)
		if dfVuln {
			dirtyFragVulnerable.Set(1)
		} else {
			dirtyFragVulnerable.Set(0)
		}
	}

	dfNeedsPatch, dfPatchDetail, dfPatchErr := detector.KernelNeedsPatchingDirtyFrag()
	if dfPatchErr != nil {
		log.Printf("Dirty Frag patch check error: %v", dfPatchErr)
	} else {
		log.Printf("Dirty Frag patch check: %s", dfPatchDetail)
		if dfNeedsPatch {
			dirtyFragKernelNeedsPatching.Set(1)
		} else {
			dirtyFragKernelNeedsPatching.Set(0)
		}
	}

	espReachable, espDetail := detector.ProbeESP()
	log.Printf("Dirty Frag ESP probe: %s", espDetail)
	if espReachable {
		dirtyFragESPReachable.Set(1)
	} else {
		dirtyFragESPReachable.Set(0)
	}

	rxrpcReachable, rxrpcDetail := detector.ProbeRxRPC()
	log.Printf("Dirty Frag RxRPC probe: %s", rxrpcDetail)
	if rxrpcReachable {
		dirtyFragRxRPCReachable.Set(1)
	} else {
		dirtyFragRxRPCReachable.Set(0)
	}

	// Remediate Dirty Frag: if any module is reachable, act based on REMEDIATION_MODE.
	if espReachable || rxrpcReachable {
		mode := strings.ToLower(strings.TrimSpace(os.Getenv("REMEDIATION_MODE")))
		if mode == "" {
			mode = "unload"
		}

		switch mode {
		case "disabled":
			log.Printf("Dirty Frag modules reachable, remediation disabled by REMEDIATION_MODE")
		case "unload":
			log.Printf("Dirty Frag modules reachable, attempting unload")
			unloaded, detail := detector.UnloadDirtyFragModules()
			log.Printf("Dirty Frag remediation: %s", detail)
			if unloaded {
				dirtyFragRemediationApplied.Set(1)
				dirtyFragESPReachable.Set(0)
				dirtyFragRxRPCReachable.Set(0)
			} else {
				dirtyFragRemediationApplied.Set(0)
			}
		case "blacklist":
			log.Printf("Dirty Frag modules reachable, attempting unload + blacklist")
			unloaded, detail := detector.UnloadDirtyFragModules()
			log.Printf("Dirty Frag remediation (unload): %s", detail)
			if unloaded {
				dirtyFragRemediationApplied.Set(1)
				dirtyFragESPReachable.Set(0)
				dirtyFragRxRPCReachable.Set(0)
			} else {
				dirtyFragRemediationApplied.Set(0)
			}
			applied, blDetail := detector.BlacklistDirtyFragModules()
			log.Printf("Dirty Frag remediation (blacklist): %s", blDetail)
			if !applied {
				dirtyFragRemediationApplied.Set(0)
			}
		default:
			log.Printf("unknown REMEDIATION_MODE %q, skipping Dirty Frag remediation", mode)
		}
	}
}

func main() {
	check()

	go func() {
		for range time.Tick(5 * time.Minute) {
			check()
		}
	}()

	log.Println("serving metrics on :9100/metrics")
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":9100", nil))
}
