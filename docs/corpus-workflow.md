# OpenClaw Version Corpus Workflow

This workflow uses the homelab Proxmox environment only for short-lived
known-version corpus testing and scanner assurance.

## Required Preflight

Read these homelab documents before any Proxmox action:

- `/Users/mhedhli/Documents/Coding/Projects/homelab/docs/infrastructure.md`
- `/Users/mhedhli/Documents/Coding/Projects/homelab/docs/vlans.md`
- `/Users/mhedhli/Documents/Coding/Projects/homelab/docs/security.md`
- `/Users/mhedhli/Documents/Coding/Projects/homelab/docs/todo.md`

Current safe defaults from those docs:

- Use VLAN 30 for standard dev/testing corpus VMs.
- Use VLAN 31 only for untrusted or hostile test cases, and only after it is
  intentionally created and documented.
- Do not place corpus VMs on Mgmt, Storage, Infra, AI, Agents, Home Automation,
  IoT, Guest, or other unrelated VLANs.
- Do not expose corpus VMs publicly or through Tailscale Serve.
- Use small VMs by default: 2 vCPU, 4 GB RAM, 40 GB disk.

## Credential Rules

- Use project-specific Proxmox credentials or tokens named for this scanner.
- Do not use root or shared credentials unless explicitly approved.
- Keep credentials outside the repo in the documented local secure path.
- Do not print passwords, tokens, keys, cookies, tickets, or authorization
  headers.
- Treat any credential shown in terminal output, screenshots, repo files, or
  logs as compromised.

## Proxmox Access Preflight

Before creating a VM, verify the project token can read the target node,
template, pool, and storage, and can use the selected network path. For VLAN 30
on `vmbr0`, Proxmox clone may require `SDN.Use` on the parent SDN path
`/sdn/zones/localnetwork/vmbr0`, not only on the VLAN-specific child path.

If any required permission is missing, do not attempt clone or boot actions.
Record the blocker, confirm no corpus VM was created, and continue only with
non-secret repo work until the token or network path is corrected.
Treat Proxmox API timeouts or TLS/network errors the same way: the lifecycle is
blocked until a later preflight produces a clean report.

Use the secret-safe preflight helper before any VM lifecycle action:

```bash
python3 scripts/proxmox_corpus_preflight.py \
  --format json \
  --output artifacts/lab/YYYY-MM-DD/proxmox-preflight.json \
  --manifest artifacts/lab/YYYY-MM-DD/manifest.json
```

The helper performs read-only API checks, reports OpenClaw/corpus VM inventory,
checks target-template readiness for cloud-init plus QEMU guest-agent IP
discovery, verifies clone cloud-init identity has a user plus SSH key source or
`cicustom`, and prints permission status without printing token, password, or
authorization header values. Preserve the JSON report alongside the lab
manifest; when `--manifest` is supplied, the helper copies the preflight
status, `vm_lifecycle_allowed`, inventory counts, template readiness, clone
identity readiness, and blockers into `manifest.json`.
If the report lists any running OpenClaw/corpus VMs, stop and cleanly account
for them before starting new VM lifecycle work.

Before launching a VM solely because a heartbeat saw package activity, generate
a release-gap report from the already-fetched package versions, saved captures,
and promoted exact rules:

```bash
python3 scripts/check_openclaw_release_gap.py \
  --versions-json "$OPENCLAW_NPM_VERSIONS_JSON" \
  --capture-root artifacts/lab \
  --output artifacts/lab/YYYY-MM-DD/openclaw-release-gap.json \
  --manifest artifacts/lab/YYYY-MM-DD/manifest.json
```

The report contains only package versions, capture counts, and promoted-rule
versions. When `--manifest` is supplied, the helper copies the sanitized
release-gap decision, latest published/captured/promoted versions, and capture
queue into `manifest.json`. If `capture_needed=false`, do not launch a VM for
that heartbeat. By default, uncaptured prereleases are reported but do not
trigger a capture decision; pass `--include-prereleases` only when prerelease
corpus coverage is intentionally desired.

For hourly heartbeat upkeep, prefer the aggregate read-only checkpoint helper
after the required repo-status and homelab-doc refresh:

```bash
python3 scripts/run_openclaw_corpus_heartbeat.py \
  --artifact-dir artifacts/lab/YYYY-MM-DD \
  --manifest artifacts/lab/YYYY-MM-DD/manifest.json \
  --capture-root artifacts/lab \
  --ignore-version <intentionally-unpromoted-version> \
  --label heartbeat-HHMM \
  --output artifacts/lab/YYYY-MM-DD/openclaw-corpus-heartbeat-HHMM.json
```

The aggregate helper fetches package versions, runs the secret-safe Proxmox
preflight, writes the release-gap report, validates saved captures with
`--require-all-exact`, updates the manifest summaries, and emits a compact
heartbeat decision. It never creates, boots, stops, or deletes VMs. If it
returns `decision=launch_single_vm_capture`, perform the normal one-VM
lifecycle flow next; if it returns `decision=no_vm_needed`, do not launch a VM
for that heartbeat.

If the cloned VM boots but the guest agent does not report an IPv4 address,
use the lifecycle helper's bounded discovery path instead of guessing or
probing the subnet:

```bash
python3 scripts/proxmox_corpus_lifecycle.py discover-ip \
  --vmid <vmid> \
  --output artifacts/lab/YYYY-MM-DD/<product>-<version>/ip-discovery.json
```

The helper polls Proxmox guest-agent output for a bounded number of attempts,
then falls back only to passive ARP/DHCP observations for the VM's exact MAC on
the expected corpus network. The fallback accepts a candidate only when the VM
config proves `bridge=vmbr0`, `tag=30`, and the candidate IPv4 is inside the
allowed VLAN 30 subnet. Do not run subnet sweeps or broad host discovery. If no
exact passive candidate exists, stop and delete the VM, preserve the
`ip-discovery.json` artifact, and record the failure as
`ip_discovery_failed_closed`.

After repeated `no_ip_discovered` outcomes with matching VLAN 30 config, guest
agent failures, and no passive MAC evidence, stop launching identical clones.
The next retry must first change one of the failed premises: repair
template/cloud-init networking, prove guest-agent readiness, or provide a
bounded DHCP/ARP evidence source that positively matches the VM MAC.

For template validation, use a diagnostic VM rather than a scanner capture:

```bash
python3 scripts/proxmox_corpus_lifecycle.py diagnose-template \
  --attempt-id <id> \
  --diagnostic-attempts 30 \
  --diagnostic-interval 10 \
  --output-dir artifacts/lab/YYYY-MM-DD/template-diagnostics \
  --manifest artifacts/lab/YYYY-MM-DD/manifest.json \
  --update-manifest \
  --output artifacts/lab/YYYY-MM-DD/template-diagnostics/proxmox-template-diagnostic-<id>.json
```

This command still creates exactly one VLAN 30 VM and destroys it in `finally`,
but it skips scanner capture. It records VM config/MAC, guest-agent ping,
guest-agent network-interface status, passive VLAN 30 MAC evidence, and
cloud-init/NIC/guest-agent command output only if guest-agent execution or a
positively MAC-matched SSH path becomes available. If `.env` provides
`OPENCLAW_PROXMOX_CIUSER` plus `OPENCLAW_PROXMOX_SSHKEYS_FILE` or
`OPENCLAW_PROXMOX_SSH_PUBLIC_KEY`, the lifecycle helper applies those
cloud-init identity settings to short-lived clones without printing key
material. Raw SSH public keys are URL-encoded for Proxmox `sshkeys` config, and
already encoded `sshkeys` values are preserved. It can also apply
`OPENCLAW_PROXMOX_CICUSTOM` when the clone should use an existing Proxmox
snippet. If the result is `no_ip_discovered`, treat that as a template/network
activation blocker before any more corpus capture attempts.
If DHCP/ARP is observed for the VM MAC but guest-agent remains unhealthy, treat
DHCP and NIC bring-up as validated and focus the next fix on
`qemu-guest-agent` installation, enablement, and boot-time service health inside
the template. If the VM accepts SSH but returns public-key denial, fix clone
cloud-init identity (`ciuser`, SSH public keys, or `cicustom`) before using SSH
as a readiness or install path.

To repair a template without mutating the source template in place, clone the
source template into one temporary VLAN 30 repair VM, install QGA over the
proven cloud-init SSH identity, reboot the clone, verify Proxmox guest-agent
runtime calls, clean cloud-init/machine-id state, shut down, and convert the
clone into a new template:

```bash
python3 scripts/proxmox_corpus_lifecycle.py repair-template \
  --attempt-id qga-01 \
  --new-template-name ubuntu-2404-cloudinit-qga \
  --output-dir artifacts/lab/YYYY-MM-DD/template-repairs \
  --manifest artifacts/lab/YYYY-MM-DD/manifest.json \
  --update-manifest \
  --output artifacts/lab/YYYY-MM-DD/template-repairs/proxmox-template-repair-qga-01.json
```

After a repaired template is created, point the ignored local env/config at the
new template VMID and rerun preflight. Do not retire or replace the original
source template until at least one known-version corpus capture succeeds from
the repaired template lineage.

## Known-Version Deployment Gate

`run-once` now fails closed before creating a VM unless a bounded deployment
path is provided. This prevents a blank Ubuntu clone from advancing to scanner
capture and producing a misleading `gateway_unreachable` result.

Use an SSH deploy command for each known-version target:

```bash
python3 scripts/proxmox_corpus_lifecycle.py run-once \
  --version <known-version> \
  --attempt-id <id> \
  --deploy-command-label openclaw-install-<known-version> \
  --deploy-command '<install/start command using {version}, {ip}, or {port}>' \
  --output-dir artifacts/lab/YYYY-MM-DD/openclaw-<known-version> \
  --manifest artifacts/lab/YYYY-MM-DD/manifest.json \
  --update-manifest
```

For longer commands, prefer keeping the exact install/start recipe in a local
ignored file and passing that file path instead of placing the command directly
in shell history:

```bash
python3 scripts/proxmox_corpus_lifecycle.py validate-deploy-command \
  --version <known-version> \
  --deploy-command-label openclaw-install-<known-version> \
  --deploy-command-file .local/openclaw-deploy-<known-version>.sh \
  --output artifacts/lab/YYYY-MM-DD/openclaw-<known-version>/deploy-command-validation.json

python3 scripts/proxmox_corpus_lifecycle.py run-once \
  --version <known-version> \
  --attempt-id <id> \
  --deploy-command-label openclaw-install-<known-version> \
  --deploy-command-file .local/openclaw-deploy-<known-version>.sh \
  --output-dir artifacts/lab/YYYY-MM-DD/openclaw-<known-version> \
  --manifest artifacts/lab/YYYY-MM-DD/manifest.json \
  --update-manifest
```

The deploy command runs only after the VM IP has been positively matched to the
VM's configured MAC on VLAN 30. `{version}`, `{ip}`, and `{port}` placeholders
are shell-quoted by the helper before execution. If `--deploy-command-file` is
used for a path inside this repo, the helper fails closed unless the file is
untracked and matched by `.gitignore`; files outside the repo are allowed for
operator-managed secret storage. The file must still be non-empty and
non-secret. The command text and command output are not written to artifacts;
only the non-secret
`--deploy-command-label`, status, return code, and reason are recorded. Do not
include secrets in deploy commands. If secrets are required for a future app
install path, pass them through pre-positioned ignored files on the guest or a
separate reviewed secret channel instead of CLI arguments.

Keep compatibility recipes version-scoped. Older release workarounds belong in
ignored per-slice deploy-command files or in documented corpus artifacts; do
not fold legacy install/start changes into modern deployment paths unless a
modern release independently requires them.

Use `--skip-deploy` only when the selected template is intentionally
pre-deployed with the exact known version being captured. Otherwise, a missing
deploy command records `deployment_failed` with reason
`deployment_not_configured` and does not create a VM.

After deployment succeeds, the helper polls `http://<ip>:18789/health` for a
bounded number of attempts. Scanner capture runs only if the gateway endpoint
returns an HTTP response. If no response is observed, the outcome is
`gateway_unreachable`; if the scanner runs but no usable capture is produced,
the outcome is `capture_failed`.

## Capture Layout

Use dated capture directories:

```text
artifacts/lab/YYYY-MM-DD/
  manifest.json
  <product>-<version>/
    scan.json
    capture.json
```

The manifest must record:

- VM name
- VM ID
- product family
- version
- IP or hostname
- port
- VLAN
- auth mode
- deployment method
- deployment result
- Proxmox preflight command and blockers
- Proxmox template readiness and clone identity readiness
- created_at
- started_at
- stopped_at
- deleted_at
- owner thread
- scanner command
- scanner result summary
- scan artifact path
- capture artifact path

A starter manifest template is available at
[`artifacts/lab/templates/manifest.template.json`](/Users/mhedhli/Documents/Codex/OpenClawScanner/artifacts/lab/templates/manifest.template.json).

## Capture Command

```bash
python3 -m openclaw_scanner \
  --target http://<host-or-ip>:18789 \
  --capture-version <known-version> \
  --capture-name <product>-<known-version> \
  --capture-output artifacts/lab/YYYY-MM-DD/<product>-<known-version>/capture.json \
  --format json \
  --output artifacts/lab/YYYY-MM-DD/<product>-<known-version>/scan.json
```

After at least two known-version captures:

```bash
python3 -m openclaw_scanner \
  --suggest-rules-from artifacts/lab/YYYY-MM-DD \
  --format json \
  --output artifacts/lab/YYYY-MM-DD/candidate-version-rules.json
```

The rule-suggestion loader recursively discovers nested `capture.json` bundles
under the dated lab directory and ignores non-capture JSON files such as
`manifest.json`, `scan.json`, and generated candidate-rule reports. The
suggestion report lists skipped input files so a missing or malformed capture is
visible during review instead of being silently ignored.

After promoting a candidate rule, validate saved captures against the current
rule set with the sanitized inference checker:

```bash
python3 scripts/validate_saved_capture_inference.py \
  --input-root artifacts/lab/YYYY-MM-DD \
  --output artifacts/lab/YYYY-MM-DD/saved-capture-inference-check.json \
  --manifest artifacts/lab/YYYY-MM-DD/manifest.json
```

The report records capture paths, declared versions, per-version summaries,
match counts, top inferred versions, and exact-match sources. It intentionally
omits target URLs, raw observation URLs, and lab IPs. When `--manifest` is
supplied, the helper copies the sanitized pass/fail summary, version summary,
ignored-version list, and skipped-input summary into `manifest.json`. Use
`--require-all-exact` only when every declared capture in the input set is
expected to have a promoted exact rule; leave it off when the lab directory
intentionally contains unpromoted or unstable captures.

If a lab directory intentionally preserves unstable captures that are not ready
for promotion, keep the check strict for promoted versions by excluding only the
known holdout versions:

```bash
python3 scripts/validate_saved_capture_inference.py \
  --input-root artifacts/lab/YYYY-MM-DD \
  --output artifacts/lab/YYYY-MM-DD/saved-capture-inference-check-promoted.json \
  --require-all-exact \
  --ignore-version <unpromoted-version> \
  --manifest artifacts/lab/YYYY-MM-DD/manifest.json
```

## Cleanup Discipline

- Boot corpus VMs only while active capture/scanning is happening.
- Shut down VMs immediately when testing stops.
- Delete version-specific VMs after artifacts are captured.
- Do not leave long-lived snapshots or orphaned disks.
- Preserve only corpus artifacts needed for scanner assurance.
