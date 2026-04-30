package main

import (
	"log"
	"net/http"
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
)

func init() {
	prometheus.MustRegister(copyFailVulnerable)
	prometheus.MustRegister(copyFailNeedsPatching)
	prometheus.MustRegister(moduleReachable)
	prometheus.MustRegister(remediationApplied)
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

	// Remediate: if the module is reachable on a vulnerable kernel, unload it.
	if reachable {
		log.Printf("module reachable (%s), attempting remediation", probeDetail)
		unloaded, detail := detector.UnloadAFALGModule()
		log.Printf("remediation: %s", detail)
		if unloaded {
			remediationApplied.Set(1)
			moduleReachable.Set(0)
		} else {
			remediationApplied.Set(0)
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
