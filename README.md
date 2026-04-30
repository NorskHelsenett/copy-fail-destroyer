# copy-fail-destroyer

A Kubernetes DaemonSet agent that detects and remediates Linux kernel vulnerabilities in the `algif_aead` subsystem:

- [CVE-2022-27666](https://nvd.nist.gov/vuln/detail/CVE-2022-27666) — ESP6 / AF_ALG heap buffer overflow
- [CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431) ("Copy Fail") — `algif_aead` in-place logic flaw allowing unprivileged page-cache writes

Both are exploitable via the `AF_ALG` socket interface and share the same remediation: unloading the `algif_aead` kernel module.

## What it does

On each node the agent runs a loop every 5 minutes that:

1. **Checks the kernel version** against all known patched stable branches.
2. **Probes the AF_ALG module** by attempting to create and bind an `AF_ALG` socket to `aead` / `authenc(hmac(sha256),cbc(aes))` — the exact algorithm the exploit targets. This is safe and non-destructive.
3. **Remediates** by unloading the `algif_aead` kernel module (`delete_module`) if the probe succeeds, removing the attack surface until the kernel can be patched.
4. **Exposes Prometheus metrics** so you can alert and track status across the fleet.

## Prometheus metrics

All metrics are exposed on `:9100/metrics`.

| Metric | Description |
|---|---|
| `cve_2022_27666_kernel_needs_patching` | `1` if the kernel version is not patched for CVE-2022-27666 |
| `cve_2022_27666_vulnerable` | `1` if the kernel is vulnerable **and** the module is reachable (actively exploitable) |
| `cve_2026_31431_kernel_needs_patching` | `1` if the kernel version is not patched for CVE-2026-31431 |
| `cve_2026_31431_vulnerable` | `1` if the kernel is vulnerable to CVE-2026-31431 **and** the module is reachable |
| `cve_2022_27666_module_reachable` | `1` if the `AF_ALG` aead algorithm can be bound |
| `cve_2022_27666_remediation_applied` | `1` if the `algif_aead` module was successfully unloaded |

## Patched kernel versions

### CVE-2022-27666

- `5.17.0+` (mainline)
- `5.16.15`, `5.15.29`, `5.10.106`, `5.4.185`
- `4.19.235`, `4.14.272`, `4.9.307`

### CVE-2026-31431 (Copy Fail)

- `7.0+` (mainline)
- `6.19.12+`, `6.18.22+`
- Kernels before `4.14` are not affected (bug introduced in 4.14)

## Project structure

```
cmd/destroyer/main.go          # Entry point — metrics server, check loop, remediation
pkg/detector/
  cve202227666.go              # CVE-2022-27666 detection, KernelNeedsPatching()
  cve202631431.go              # CVE-2026-31431 (Copy Fail) detection
  probe_linux.go               # AF_ALG module probe (Linux)
  probe_other.go               # Probe stub (non-Linux)
  remediate_linux.go           # Module unload via delete_module (Linux)
  remediate_other.go           # Remediation stub (non-Linux)
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

The agent runs in a dedicated namespace with a `privileged` Pod Security Admission policy. The container itself is **not** fully privileged — it only requests the specific capabilities it needs:

- `CAP_SYS_MODULE` — to unload `algif_aead` via `delete_module`
- `CAP_NET_ADMIN` — to create `AF_ALG` sockets for probing

All other capabilities are dropped, and the root filesystem is read-only.

```bash
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/daemonset.yaml
```

The DaemonSet includes Prometheus scrape annotations (`prometheus.io/scrape: "true"`, port `9100`).

## CI/CD

A GitHub Actions workflow (`.github/workflows/build.yaml`) triggers on versioned tags (`v*`). It:

1. Runs `go test ./...`
2. Builds the Linux binary
3. Builds and pushes a container image to `ghcr.io/norskhelsenett/copy-fail-destroyer`

Tags are derived from the Git tag — e.g. pushing `v1.2.3` produces image tags `1.2.3` and `1.2`.

```bash
git tag v1.0.0
git push origin v1.0.0
```