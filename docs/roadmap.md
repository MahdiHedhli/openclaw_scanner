# OpenClaw Scanner Roadmap

This roadmap captures suggestions that fit the scanner's current scope:
external, passive, internal unauthenticated, and controlled-lab fingerprinting
for OpenClaw-family gateways. Host-side scanning and destructive probing remain
out of scope unless explicitly approved.

## Current State

- Exact version fingerprinting is now usable for the promoted lab corpus, not
  merely blocked on corpus availability. The bundled rule set includes 17
  exact, lab-promoted OpenClaw versions from short-lived VLAN 30 captures:
  `2026.1.29-beta.1`, `2026.2.2-1`, `2026.2.6`, `2026.2.13`, `2026.2.21`,
  `2026.5.3-1`, `2026.5.7`, `2026.5.18`, `2026.5.19-beta.1`, `2026.5.20`,
  `2026.5.22`, `2026.5.24-beta.1`, `2026.5.24-beta.2`, and
  `2026.5.25-beta.1`, `2026.5.26`, `2026.5.27`, and `2026.5.28`.
- The 2026-06-02 release-watch run closed the stable package gap through
  `2026.5.28`. Later prereleases remain visible in release-gap reports but do
  not trigger VM work unless prerelease coverage is explicitly requested.
- Family classification is useful today, but many live signals do not map to a
  specific release without lab calibration.
- Discovery now supports reusable Shodan query definitions, normalized Censys
  and FOFA imports, passive CT import filtering, discovery confidence/source
  metadata, and opt-in alternate-port probing for likely gateway hosts.
- Default active validation is GET/WebSocket-only. Conditional deep validation
  runs only after a strong OpenClaw-family fingerprint and can collect
  presence/status/header/shape signals for Socket.IO polling, noVNC,
  websockify, CORS preflight, OpenAI-compatible GET routes, browser-tool
  routes, canvas routes, and WebSocket upgrades. POST probes are a separate
  explicit operator opt-in.
- Passive discovery is useful for candidate discovery but does not provide
  reliable exact-version fingerprinting in the current field data. Discovery
  confidence, passive TLS/JARM, passive CT names, and generic passive banner
  text must not drive vulnerability correlation.
- Exact-version attribution still requires lab-promoted remote-visible rules or
  explicit correlation-grade metadata such as package or `cliPath` mDNS
  versions. CDP/Chromium signals are browser-agent evidence and not standalone
  OpenClaw proof.
- Proxy, WAF, TLS termination, and deployment-specific auth modes can hide or
  distort backend behavior.
- Vulnerability triage should remain conservative unless an exact or strongly
  corroborated approximate version is inferred.
- Lab infrastructure must stay short-lived, segmented, and fully documented.
- Proxmox-backed corpus VM lifecycle now has passing VLAN 30 permission,
  template, and clone cloud-init identity preflight coverage. VM network
  discovery remains bounded and MAC-driven across guest-agent, ARP, DHCP, and
  short-lived SSH evidence. VM 9000 was preserved, and a repaired derivative
  template `ubuntu-2404-cloudinit-qga` was created with QGA installed. A
  diagnostic clone from that repaired template reported a Proxmox guest-agent
  IPv4 address and was stopped/deleted cleanly. The lifecycle requires a
  bounded known-version SSH deploy command, or an explicit pre-deployed-image
  override, before gateway health polling and scanner capture.
- Known-vulnerable legacy releases have a separate ignored deployment recipe
  path so compatibility workarounds do not leak into modern-version deployment
  recipes.

## Priority Roadmap

1. Continue expanding the known-version corpus beyond the 17 promoted exact
   rules, with at least two captures per version before promotion.
2. Derive stable favicon hashes from saved lab captures and validate them before
   adding favicon-driven discovery queries or family rules.
3. Improve `--suggest-rules-from` with stability, uniqueness, and weighted
   confidence scoring.
4. Deepen static asset analysis for `/asset-manifest.json`, `/manifest.json`,
   JS/CSS chunks, build hashes, and runtime/version strings.
5. Expand passive enrichment for CPE, JARM, favicon hashes, hostnames, domains,
   mDNS TXT records, Shodan CVE context, Censys/FOFA title/TLS fields, and CT
   naming indicators.
6. Add a risk score that combines version confidence, auth exposure, exposed
   endpoint families, proxy/honeypot assessment, and vulnerability severity.
7. Add safer internet-facing scan ergonomics such as explicit authorization
   warnings, rate-limit controls, and conservative defaults for public target
   lists.
8. Calibrate conditional deep-validation presence signals so Socket.IO, noVNC,
   websockify, and CORS behavior improve clustering without becoming exact
   version or vulnerability-correlation evidence.

## Valid Follow-On Ideas

- Add lightweight signal similarity in candidate rule generation, such as
  Jaccard similarity for JSON keys and normalized header-order distance.
- Keep optional clustering as an offline analysis helper after enough capture
  bundles exist; do not add a mandatory ML dependency to the scanner.
- Parse OpenAI-compatible endpoint responses and error shapes more deeply,
  especially `/v1/models` when it returns real JSON rather than SPA fallback.
- Continue WebSocket handshake fingerprinting and reserve message-level
  WebSocket probing for lab-only or explicit `--deep` mode.
- Improve skill/plugin surface mapping for unauthenticated endpoints such as
  `/api/skills`, `/api/agents`, `/api/devices`, `/tools`, and `/tools/invoke`.
- Add SARIF or STIX export only after the core JSON/CSV/NDJSON schema stabilizes.
- Track observed instances locally with SQLite once repeated scans are common.

## Deferred Or Opt-In Only

- `DELETE /`, malformed request probes, directory brute forcing, and WebSocket
  message reads should not be default internet-scan behavior.
- Docker daemon or registry probing should be passive-first via Shodan and only
  active in explicit `--deep` or lab mode.
- VNC interaction, debugger WebSocket attachment, authenticated requests, and
  tool-execution payloads should remain out of scope for internet-facing scans.
- Public exploit snippets should not be embedded in output. Advisory and PoC
  references are acceptable when clearly labeled.
- BinaryEdge, Hunter.io, active CT enumeration, active TLS/JARM probing, JA3S,
  and HTTP/2 probing should remain deferred or opt-in until passive imports and
  saved-capture validation are better calibrated.
