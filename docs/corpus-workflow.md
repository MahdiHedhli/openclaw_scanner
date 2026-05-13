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
- created_at
- started_at
- stopped_at
- deleted_at
- owner thread
- scanner command
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

## Cleanup Discipline

- Boot corpus VMs only while active capture/scanning is happening.
- Shut down VMs immediately when testing stops.
- Delete version-specific VMs after artifacts are captured.
- Do not leave long-lived snapshots or orphaned disks.
- Preserve only corpus artifacts needed for scanner assurance.
