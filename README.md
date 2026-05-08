# copy-fail-destroyer

A Kubernetes DaemonSet agent that detects and remediates [CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431) ("Copy Fail") and [Dirty Frag](https://github.com/V4bel/dirtyfrag) — Linux kernel page-cache write vulnerabilities allowing unprivileged root escalation.

### Copy Fail (CVE-2026-31431)

An `algif_aead` in-place logic flaw allowing unprivileged page-cache writes via the `AF_ALG` socket interface.

### Dirty Frag

Two chained page-cache write vulnerabilities:

- **xfrm-ESP Page-Cache Write**: `esp_input()` bypasses `skb_cow_data()` for non-linear skbs, allowing in-place crypto on attacker-pinned page-cache pages. Requires `esp4`/`esp6` modules + user namespace privileges. Introduced in kernel 4.10 (2017).
- **RxRPC Page-Cache Write**: `rxkad_verify_packet_1()` performs in-place `pcbc(fcrypt)` decrypt on page-cache frags. Requires `rxrpc` module but **no namespace privileges**. Introduced in kernel 6.4 (2023).

The exploit chains both variants — if one is blocked, the other fills the gap. A system is vulnerable if **either** module is reachable.

## What it does

On each node the agent runs a loop every 5 minutes that:

1. **Checks the kernel version** against all known patched stable branches.
2. **Probes attack-surface modules**:
   - **Copy Fail**: attempts to create and bind an `AF_ALG` socket to `aead` / `authenc(hmac(sha256),cbc(aes))` — the exact algorithm the exploit targets. Safe and non-destructive.
   - **Dirty Frag**: checks whether `esp4`, `esp6`, or `rxrpc` modules are loaded or available on disk. Does **not** create sockets that would trigger module autoloading.
3. **Remediates** based on the configured `REMEDIATION_MODE` (see below).
4. **Exposes Prometheus metrics** so you can alert and track status across the fleet.

## Remediation modes

Set via the `REMEDIATION_MODE` environment variable (or `remediationMode` in the Helm chart):

| Mode | Behaviour |
|---|---|
| `unload` (default) | Unloads the `algif_aead`, `esp4`, `esp6`, and `rxrpc` kernel modules via `delete_module` |
| `blacklist` | Unloads the modules **and** writes modprobe blacklist rules to prevent auto-reload |
| `disabled` | Detect and report only — no remediation is performed |

## Prometheus metrics

All metrics are exposed on `:9100/metrics`.

| Metric | Description |
|---|---|
| `cve_2026_31431_kernel_needs_patching` | `1` if the kernel version is not patched for CVE-2026-31431 |
| `cve_2026_31431_vulnerable` | `1` if the kernel is vulnerable to CVE-2026-31431 **and** the module is reachable |
| `cve_2026_31431_module_reachable` | `1` if the `AF_ALG` aead algorithm can be bound |
| `cve_2026_31431_remediation_applied` | `1` if the `algif_aead` module was successfully unloaded |
| `dirty_frag_vulnerable` | `1` if the kernel is vulnerable to Dirty Frag (ESP or RxRPC) **and** modules are reachable |
| `dirty_frag_kernel_needs_patching` | `1` if the kernel version is not patched for Dirty Frag (either variant) |
| `dirty_frag_esp_module_reachable` | `1` if `esp4` or `esp6` is loaded or available on disk |
| `dirty_frag_rxrpc_module_reachable` | `1` if `rxrpc` is loaded or available on disk |
| `dirty_frag_remediation_applied` | `1` if Dirty Frag module mitigations have been applied |

## Patched kernel versions

### CVE-2026-31431 (Copy Fail)

- `7.0+` (mainline)
- `6.19.12+`, `6.18.22+`
- Kernels before `4.14` are not affected (bug introduced in 4.14)

### Dirty Frag

- **ESP variant**: introduced in kernel `4.10` (`cac2661c53f3`, 2017). Patch merged into netdev tree 2026-05-07 (`f4c50a4034e6`). No stable release contains the fix yet.
- **RxRPC variant**: introduced in kernel `6.4` (`2dc334f1a63a`, 2023). Patch submitted but **not merged upstream** as of 2026-05-08.
- No CVE assigned. Version checks will be updated when distros backport patches.

## Project structure

```
cmd/destroyer/main.go          # Entry point — metrics server, check loop, remediation
pkg/detector/
  cve202631431.go              # CVE-2026-31431 (Copy Fail) detection
  dirtyfrag.go                 # Dirty Frag detection (ESP + RxRPC variants)
  probe_linux.go               # AF_ALG module probe (Linux)
  probe_other.go               # Probe stub (non-Linux)
  probe_dirtyfrag_linux.go     # ESP, RxRPC, user namespace probes (Linux)
  probe_dirtyfrag_other.go     # Probe stubs (non-Linux)
  remediate_linux.go           # algif_aead unload via delete_module (Linux)
  remediate_other.go           # Remediation stub (non-Linux)
  remediate_dirtyfrag_linux.go # esp4/esp6/rxrpc unload + blacklist (Linux)
  remediate_dirtyfrag_other.go # Remediation stubs (non-Linux)
deploy/namespace.yaml          # Namespace with Pod Security Admission policy
deploy/daemonset.yaml          # Kubernetes DaemonSet manifest
Dockerfile                     # Multi-stage build (scratch final image)
```

## Building

```bash
# Native
go build ./cmd/destroyer

# Linux cross-compile (for container image)
CGO_ENABLED=0 GOOS=linux go build -o destroyer ./cmd/destroyer
```

## Container image

```bash
docker build -t copy-fail-destroyer .
```

## Deployment

The agent requires a privileged security context to unload kernel modules and probe `AF_ALG` sockets. The root filesystem is read-only.

### Raw manifests

```bash
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/daemonset.yaml
```

### Helm

```bash
helm install copy-fail-destroyer oci://ghcr.io/norskhelsenett/helm/copy-fail-destroyer \
  --namespace copy-fail-destroyer --create-namespace
```

Override the remediation mode:

```bash
helm install copy-fail-destroyer oci://ghcr.io/norskhelsenett/helm/copy-fail-destroyer \
  --namespace copy-fail-destroyer --create-namespace \
  --set remediationMode=disabled
```

### ArgoCD

An Application manifest is provided at `deploy/argocd-application.yaml`. Edit `targetRevision` to pin a chart version:

```bash
kubectl apply -f deploy/argocd-application.yaml
```

The DaemonSet includes Prometheus scrape annotations (`prometheus.io/scrape: "true"`, port `9100`).

### Prometheus Operator

If you use the Prometheus Operator, deploy the `PodMonitor` to have metrics scraped automatically:

```bash
# Raw manifest
kubectl apply -f deploy/podmonitor.yaml

# Or via Helm
helm install copy-fail-destroyer oci://ghcr.io/norskhelsenett/helm/copy-fail-destroyer \
  --namespace copy-fail-destroyer --create-namespace \
  --set metrics.podMonitor.enabled=true
```

Alert rules (`PrometheusRule`) for Alertmanager are also available:

```bash
# Raw manifest
kubectl apply -f deploy/prometheusrule.yaml

# Or via Helm with extra alert labels
helm install copy-fail-destroyer oci://ghcr.io/norskhelsenett/helm/copy-fail-destroyer \
  --namespace copy-fail-destroyer --create-namespace \
  --set metrics.prometheusRule.enabled=true \
  --set metrics.prometheusRule.extraAlertLabels.team=platform
```

Three alerts are defined:

| Alert | Severity | Description |
|---|---|---|
| `CopyFailVulnerable` | critical | Kernel is vulnerable **and** AF_ALG module is reachable |
| `CopyFailKernelNeedsPatching` | warning | Kernel version is unpatched (module may be mitigated) |
| `CopyFailRemediationFailed` | warning | Module still reachable after remediation attempt |
| `DirtyFragVulnerable` | critical | Kernel is vulnerable **and** ESP or RxRPC modules are reachable |
| `DirtyFragKernelNeedsPatching` | warning | Kernel version is unpatched for Dirty Frag |
| `DirtyFragRemediationFailed` | warning | Dirty Frag modules still reachable after remediation attempt |

## CI/CD

A GitHub Actions workflow (`.github/workflows/build.yaml`) triggers on versioned tags (`v*`). It:

1. Runs `go test ./...`
2. Builds the Linux binary
3. Builds and pushes a container image to `ghcr.io/norskhelsenett/copy-fail-destroyer`
4. Packages and pushes the Helm chart to `oci://ghcr.io/norskhelsenett/helm/copy-fail-destroyer`

Tags are derived from the Git tag — e.g. pushing `v1.2.3` produces image tags `1.2.3` and `1.2`.

```bash
git tag v1.0.0
git push origin v1.0.0
```