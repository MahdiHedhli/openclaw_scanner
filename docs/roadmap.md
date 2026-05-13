# OpenClaw Scanner Roadmap

This roadmap captures suggestions that fit the scanner's current scope:
external, passive, internal unauthenticated, and controlled-lab fingerprinting
for OpenClaw-family gateways. Host-side scanning and destructive probing remain
out of scope unless explicitly approved.

## Current Roadblocks

- Exact version fingerprinting is blocked on a labeled known-version corpus.
- Family classification is useful today, but many live signals do not map to a
  specific release without lab calibration.
- Proxy, WAF, TLS termination, and deployment-specific auth modes can hide or
  distort backend behavior.
- Vulnerability triage should remain conservative unless an exact or strongly
  corroborated approximate version is inferred.
- Lab infrastructure must stay short-lived, segmented, and fully documented.

## Priority Roadmap

1. Build a known-version corpus from short-lived lab nodes.
2. Improve `--suggest-rules-from` with stability, uniqueness, and weighted
   confidence scoring.
3. Deepen static asset analysis for `/asset-manifest.json`, `/manifest.json`,
   JS/CSS chunks, build hashes, and runtime/version strings.
4. Expand passive Shodan enrichment for CPE, JARM, favicon hashes, hostnames,
   domains, mDNS TXT records, and Shodan CVE context.
5. Add a risk score that combines version confidence, auth exposure, exposed
   endpoint families, proxy/honeypot assessment, and vulnerability severity.
6. Add corpus automation that can create, scan, capture, shut down, and destroy
   test nodes reproducibly.

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
- Public exploit snippets should not be embedded in output. Advisory and PoC
  references are acceptable when clearly labeled.
- Censys, BinaryEdge, Hunter.io, CT logs, and other pivots should follow after
  Shodan ingestion and the lab corpus are stable.
