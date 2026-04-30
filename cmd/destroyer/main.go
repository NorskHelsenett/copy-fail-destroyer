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
	kernelVulnerable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cve_2022_27666_vulnerable",
		Help: "1 if the kernel is vulnerable to CVE-2022-27666, 0 otherwise.",
	})
	moduleReachable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cve_2022_27666_module_reachable",
		Help: "1 if the AF_ALG module and algorithm are reachable, 0 otherwise.",
	})
	remediationApplied = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cve_2022_27666_remediation_applied",
		Help: "1 if the algif_aead module was successfully unloaded, 0 otherwise.",
	})
	kernelNeedsPatching = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cve_2022_27666_kernel_needs_patching",
		Help: "1 if the kernel version is not patched for CVE-2022-27666, 0 otherwise.",
	})
)

func init() {
	prometheus.MustRegister(kernelVulnerable)
	prometheus.MustRegister(moduleReachable)
	prometheus.MustRegister(remediationApplied)
	prometheus.MustRegister(kernelNeedsPatching)
}

func check() {
	vulnerable, reason, err := detector.IsVulnerableCVE202227666()
	if err != nil {
		log.Printf("check error: %v", err)
		return
	}

	log.Printf("check: %s", reason)

	needsPatching, patchDetail, patchErr := detector.KernelNeedsPatching()
	if patchErr != nil {
		log.Printf("patch check error: %v", patchErr)
	} else {
		log.Printf("patch check: %s", patchDetail)
		if needsPatching {
			kernelNeedsPatching.Set(1)
		} else {
			kernelNeedsPatching.Set(0)
		}
	}

	if vulnerable {
		kernelVulnerable.Set(1)
	} else {
		kernelVulnerable.Set(0)
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
