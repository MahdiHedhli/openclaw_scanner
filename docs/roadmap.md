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
- A 2026-06-03 title-query calibration processed 500 passive Shodan candidates
  and actively validated a 100-host shortlist. Passive metadata alone produced
  0 family matches, 0 exact versions, and 0 vulnerability correlations. Active
  default validation produced 70 family matches, 25 exact-version matches, and
  10 vulnerability correlations; `--deep-validation` with POST probes disabled
  preserved those counts while increasing response-shape detail.
- Public calibration review found 65 passive rows at `product_confidence=1.0`
  that correctly produced 0 exact versions and 0 vulnerability correlations.
  Passive-noise downgrade metadata now covers obvious non-OpenClaw products such
  as Ivanti EPMM, Sophos SSL VPN, D-Link webcam, Ncat proxy, IIS, and generic
  Apache/default-site banners.
- The repo now includes a public-safe GitHub Pages checker site under `site/`
  plus a Cloudflare Worker API under `cloudflare/worker/`. GitHub Pages remains
  UI only; scanning belongs in the separate rate-limited backend with CAPTCHA,
  authorization acknowledgement, SSRF protections, GET-only probes, and
  high-level output.
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
3. Promote `status_distribution_signature` from a raw observation into an
   offline clustering/reporting helper for deployment-mode and reverse-proxy
   analysis. Keep it out of exact-version and vulnerability-correlation logic
   until supported by saved-capture validation.
4. Improve `--suggest-rules-from` with stability, uniqueness, and weighted
   confidence scoring.
5. Deepen static asset analysis for `/asset-manifest.json`, `/manifest.json`,
   JS/CSS chunks, build hashes, and runtime/version strings.
6. Expand passive enrichment for CPE, JARM, favicon hashes, hostnames, domains,
   mDNS TXT records, Shodan CVE context, Censys/FOFA title/TLS fields, and CT
   naming indicators.
7. Add a risk score that combines version confidence, auth exposure, exposed
   endpoint families, proxy/honeypot assessment, and vulnerability severity.
8. Add safer internet-facing scan ergonomics such as explicit authorization
   warnings, rate-limit controls, active scan deadlines, resume files, and
   conservative defaults for public target lists.
9. Calibrate conditional deep-validation presence signals so Socket.IO, noVNC,
   websockify, and CORS behavior improve clustering without becoming exact
   version or vulnerability-correlation evidence.
10. Finish production exposure-checker deployment by creating the real
    Turnstile widget, setting the Worker secret, updating the final Pages
    origin in Worker CORS, and validating the live rate-limit and SSRF paths.
11. Use `--calibration-candidates-from` on anonymized active results to mine
    high-signal/no-family rows such as `200:35;400:2;404:1` without exposing
    real IPs, organizations, or hostnames.

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
