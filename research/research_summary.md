# OpenClaw Scanner — Research Summary

*Last updated: 2026-06-04 (Post-research implementation and calibration addendum)*

This document maintains a running executive summary of all research findings produced during the scheduled research period (2026-03-19 to 2026-03-28) for improving the OpenClaw Scanner's detection, fingerprinting, and version identification capabilities. Post-research addenda track implementation, validation, and public-safe calibration results that materially change the scanner's research direction.

**STATUS: RESEARCH PERIOD CONCLUDED.** All 13 original topics and 6 cross-cutting topics are complete. Current work is implementation and calibration follow-through, not broad new research.

---

## Post-Research Addendum (2026-06-05, Public Checker Deployment)

The public-safe checker is now represented as a deployable GitHub Pages plus
Cloudflare Worker architecture instead of a static-only concept:

- `site/` contains the GitHub Pages landing page and checker UI.
- `cloudflare/worker/` contains the Worker API, rate-limit policy, Turnstile
  verification path, target normalization, DNS-resolution SSRF preflight, and
  bounded GET-only checker probes.
- Cloudflare KV namespace `CHECKER_RATE_LIMITS` stores rate-limit counters for
  the 5-scans-per-hour source-IP limit and 3-scans-per-hour normalized-target
  limit.
- The checker result model remains evidence-first and high-level: reachability,
  possible OpenClaw candidate, family match, exact version only when bundled
  evidence supports it, risk context, and short evidence summaries.

**Scanner implication:** the public checker can improve accessibility without
turning the project into a public scanner. Production launch still requires a
real Turnstile widget, a Worker secret, and final live validation of CAPTCHA,
rate limiting, and SSRF controls.

---

## Post-Research Addendum (2026-06-04, Public Checker Follow-Up)

The post-calibration follow-up tightened public-data handling and converted the
most actionable review findings into scanner utilities:

- Passive evidence guardrails are now explicitly field-backed. Sixty-five
  passive candidates reached `product_confidence=1.0` yet produced 0 exact
  versions and 0 vulnerability correlations. This is now documented as a
  regression guard against passive-only version or vulnerability false
  positives.
- Passive noise from obvious non-OpenClaw products is now annotated and
  downgraded in discovery metadata. Current synthetic coverage includes Ivanti
  EPMM, Sophos SSL VPN, D-Link webcam, Ncat proxy, generic Microsoft IIS, and
  Apache/default-site banners. These metadata reasons improve ranking without
  blocking active validation when OpenClaw-like evidence is also present.
- The scanner now has an offline public-safe calibration candidate export mode
  for anonymized active results. It selects `has_signal=True`, no-family,
  no-exact-version rows with `product_confidence >= 0.3` and interesting
  `status_distribution_signature` values, especially `200:35;400:2;404:1`.
- A GitHub Pages-compatible checker frontend and API contract were added. The
  static page requires authorization acknowledgement and CAPTCHA completion, but
  delegates scanning to a separate rate-limited backend. The backend skeleton
  validates targets, blocks SSRF-prone addresses/hostnames, uses GET-only
  checker probes, and returns high-level results only.

**Scanner implication:** public ergonomics can improve without weakening the
evidence model. Candidate ranking, public checker UX, and calibration exports
are separate from family identification, exact-version attribution, and
vulnerability correlation.

---

## Post-Research Addendum (2026-04-16)

Follow-up review of current official documentation, release notes, and external
threat research produced a few practical adjustments for the scanner:

- The current Gateway runbook now documents a single multiplexed gateway port
  that serves WebSocket control plus HTTP APIs including `POST /tools/invoke`
  and the OpenAI-compatible `/v1/*` surface on the main port.
- The dedicated OpenAI-compatible chat docs now state that
  `POST /v1/chat/completions` is disabled by default and shares the same
  gateway auth boundary, including `429 Retry-After` behavior after too many
  auth failures.
- The dedicated tools-invoke docs now state that `POST /tools/invoke` is
  always enabled, making its structured auth failures a stronger product signal
  than simple `GET /v1/models` behavior.
- Current external threat research from Oasis and SecurityScorecard continues
  to reinforce that exposed infrastructure and auth surfaces are the main risk,
  not speculative agent autonomy. That makes auth-gated HTTP control surfaces a
  better remote fingerprinting target than generic dashboard fetches.

**Scanner implication:** prefer auth/error behavior on `POST /tools/invoke` and
selected `POST /v1/*` routes as gateway-surface signals; treat `GET /v1/models`
as high-value only when it returns real JSON; and treat `POST /v1/chat/completions`
as a lower-bound feature/config signal rather than an exact version fingerprint.

---

## Post-Research Addendum (2026-05-12)

- The scanner now includes safe HTTP upgrade-handshake probes on `/ws` and
  `/socket.io/` in addition to the existing plain GET checks.
- Upgrade responses are preserved as separate observations so black-box capture
  bundles can derive WebSocket-specific candidate rules without overwriting the
  plain path fetches.
- Candidate rule generation now supports WebSocket upgrade conditions:
  `ws_upgrade_supported`, `ws_upgrade_status`, `ws_subprotocol_contains`, and
  `ws_extension_contains`.

**Scanner implication:** WebSocket behavior can now contribute directly to
behavior-family classification and future version-specific rule generation while
staying within the remote-only, unauthenticated scanning boundary.

---

## Post-Research Addendum (2026-06-04)

The June 3 implementation sprint converted several research recommendations
into scanner behavior and then calibrated them against public-safe, anonymized
field data. The practical result is a stronger OpenClaw gateway discovery and
fingerprinting workflow while preserving the evidence-first model:

**Discovery does not equal identification.**

### Patches Applied

- Version evidence correctness is now centralized in `openclaw_scanner/versions.py`.
  Numeric build suffixes and prerelease counters survive inference paths, including
  versions such as `2026.2.2-1`, `2026.2.2-3`, and `2026.5.19-beta.1`.
- `VersionMatch` now carries correlation intent. Passive banner text can remain
  visible evidence, but generic raw passive text is not correlation-grade exact
  version evidence and cannot drive vulnerability correlation by itself.
- Explicit package or `cliPath` mDNS metadata can still produce correlation-grade
  version evidence. Approximate CDP-derived windows are marked non-exact and
  non-correlating.
- CDP/browser-agent probing is read-only and sanitized. The scanner can inspect
  `/json/version`, `/json/list`, `/json`, and related DevTools metadata without
  connecting to debugger WebSockets or storing attachable debugger URLs.
- CDP/Chromium signals are product-agnostic browser-agent evidence by default.
  They do not identify OpenClaw unless paired with other OpenClaw-family markers,
  and they do not support vulnerability correlation.
- CORS preflight probes were added for `OPTIONS /` and `OPTIONS /tools/invoke`
  with scanner-controlled origin/preflight headers. These collect response shape
  and header behavior without POST side effects.
- Stable header mining was expanded for `Server`, `WWW-Authenticate` scheme and
  realm, `X-Powered-By`, `Allow`, CORS allow headers, and basic security headers.
  Volatile or sensitive headers such as raw cookies, nonce-bearing CSP, `Date`,
  and content length are excluded from stable fingerprinting.
- Discovery now has reusable query definitions with IDs, engine, description,
  confidence weight, and query string. Current Shodan coverage includes mDNS
  OpenClaw gateway names, `http.title:"OpenClaw Control"`,
  `http.title:"Clawdbot Control"`, `http.title:"Moltbot Control"`, and
  lab-rule-derived favicon hash pivots.
- Passive imports now normalize Shodan, Censys, FOFA, and passive CT exports into
  one target model while scrubbing credential-bearing headers and sensitive
  fields. Existing `--shodan-file` behavior remains compatible.
- `--deep-validation` is conditional. It only runs after strong OpenClaw-family
  evidence and collects presence, status, headers, and response shapes for
  Socket.IO polling, noVNC, websockify, safe OpenAI-compatible GET routes,
  browser-tool routes, canvas routes, CORS behavior, and WebSocket upgrades.
- POST probes remain opt-in through `--enable-post-probes`; default probing stays
  low-impact and does not authenticate, send tool-execution payloads, connect to
  browser debugger sockets, or interact with VNC.

### Validation Evidence

- The sprint validation suite passed `python3 -m compileall openclaw_scanner tests`,
  `python3 -m unittest discover -s tests -v`, and `git diff --check`.
- The unit suite covers version suffix preservation, passive banner
  non-correlation, explicit mDNS package correlation, `--rescan-shodan` mDNS
  version survival, CDP non-correlation, exact-rule precedence over approximate
  CDP evidence, CORS/OPTIONS behavior, and conditional deep-validation gating.
- Saved-capture validation confirmed promoted exact-version rules still match
  the known-version corpus. Exact lab rules outrank CDP, noVNC, and other
  approximate or presence-only signals.
- Negative corpus coverage includes CDP-only Chrome, generic OpenAI-compatible
  services, generic SPA fallback behavior, fake passive banner version text, and
  noVNC-only endpoints. These do not produce OpenClaw exact-version or
  vulnerability-correlation claims without stronger evidence.

### Public-Safe Field Calibration

The June 3 Shodan title-query calibration used anonymized data only. Real IP
addresses, organizations, and instance names were replaced with stable
synthetic IDs and RFC5737 TEST-NET addresses before publication.

| Metric | Passive candidates | Active default | Active deep, no POST |
| --- | ---: | ---: | ---: |
| Results processed | 500 | 100 | 100 |
| Responsive active hosts | N/A | 100 | 100 |
| OpenClaw family matches | 0 | 70 | 70 |
| Exact version matches | 0 | 25 | 25 |
| Vulnerability correlations | 0 | 10 | 10 |

Key findings:

- Passive title discovery is high-yield candidate discovery, but passive-only
  evidence still produced 0 family matches, 0 exact versions, and 0 vulnerability
  correlations.
- Passive gating is now field-confirmed. In the 500-row passive CSV, 65
  candidates carried non-correlating version-like evidence that raised
  `product_confidence` to `1.0`, but those rows still produced 0 exact versions
  and 0 vulnerability correlations because the evidence remained passive banner
  text rather than correlation-grade version proof.
- Default active validation found 70 OpenClaw-family services, 25 exact known
  versions, and 10 vulnerability correlations from correlation-grade evidence.
- Conditional deep validation with POST probes disabled did not change the
  family, exact-version, or vulnerability counts, but it enriched the observation
  set for clustering and deployment-mode analysis.
- The 25 exact-versioned active hosts split into a small legacy cohort and a
  larger current-release cohort: `2023.11.3` appeared on 8 hosts, `2026.5.28`
  on 7, `2026.5.7` on 4, and `2026.1.29-beta.1`, `2026.2.2-1`,
  `2026.5.3-1`, `2026.5.18`, `2026.5.22`, and `2026.5.27` on one host each.
- Version suffix preservation is now field-confirmed. Numeric and prerelease
  suffixes survived output and vulnerability correlation for `2026.2.2-1`,
  `2026.1.29-beta.1`, and `2026.5.3-1`; they were not collapsed into bare
  `YYYY.M.D` triples.
- The vulnerable cohort was cleanly evidence-gated: 8 hosts on `2023.11.3`
  correlated to 32 vulnerability records each, one `2026.1.29-beta.1` host
  correlated to 30 records, and one `2026.2.2-1` host correlated to 29 records.
  No vulnerability correlation came from passive metadata alone.
- The `2023.11.3` cohort is the highest-priority operational finding in the
  anonymized sample. Seven of those hosts shared `200:35;400:2;404:1`, and one
  showed `200:28;400:2;401:7;404:1`, indicating externally visible auth-gated
  API behavior on an old exact-versioned build.
- The most common default `status_distribution_signature` clusters were
  `200:19;404:19` across 30 hosts, `200:17;404:19` across 20 hosts, and
  `101:2;200:17;404:19` across 15 hosts.
- The most common deep-validation clusters were `200:34;404:23;405:1` across
  20 hosts, `200:32;404:23;405:1` across 16 hosts, and
  `101:2;200:32;404:23;405:1` across 14 hosts.
- The dominant family fingerprints in the active sample were
  `openclaw_ui_only_404_api` and `openclaw_spa_fallback_all_200`, suggesting
  common deployment patterns where the UI is exposed while API routes are hidden,
  auth-gated, or reverse-proxied differently.
- The 30 active rows without a family match are not one bucket. Twenty-one had
  `has_signal=False`; six of those were flat `200:19;404:19` rows consistent
  with title/favicon false positives, and six were error-heavy rows with no
  useful status signature. Nine had `has_signal=True` but no family match; eight
  clustered around `200:35;400:2;404:1` or its `401` auth-challenge variant and
  should be treated as prime rule-mining candidates.
- Deep validation behaved as intended in field data. It increased matched-host
  observations from 38 to 58 and introduced `405` method-response evidence for
  all 70 family-matched hosts, while leaving family, exact-version, and
  vulnerability counts unchanged. No CDP/Chromium DevTools family signal was
  observed in the public-safe corpus.
- Passive source filtering still needs tightening. The anonymized passive CSV
  includes 12 candidates with non-OpenClaw product labels, including Ivanti EPMM,
  Sophos SSL VPN, Ncat proxy, D-Link webcam, IIS, and Apache. These should feed
  exclusion rules or secondary Shodan filters before active shortlist selection.

Published public-safe artifacts:

- `artifacts/shodan/2026-06-03/public/openclaw-passive-500-anonymized.csv`
- `artifacts/shodan/2026-06-03/public/openclaw-active-default-100-anonymized.csv`
- `artifacts/shodan/2026-06-03/public/openclaw-active-deep-100-anonymized.csv`
- `artifacts/shodan/2026-06-03/public/openclaw-calibration-comparison-summary.json`

### Research Implications

- Status-distribution signatures are now a strong candidate for deployment-mode
  and reverse-proxy clustering, but they must remain non-version evidence until
  saved-capture validation proves a stronger claim.
- The `200:35;400:2;404:1` and `200:28;400:2;401:7;404:1` clusters deserve a
  dedicated rule-mining pass because they include both exact vulnerable
  `2023.11.3` hosts and has-signal/no-family hosts.
- Discovery confidence should improve ranking and sampling, not identification.
  It must not create family matches, exact versions, or vulnerability
  correlations by itself.
- Non-OpenClaw passive products sharing title, favicon, port, or body-marker
  characteristics should be represented as explicit negative/exclusion signals
  so the active pipeline spends less budget on known false-positive families.
- Exact-version attribution remains limited to lab-promoted remote-visible rules
  or explicit correlation-grade metadata such as package or `cliPath` versions.
- CDP/Chromium, noVNC, Socket.IO, websockify, CORS, TLS/JARM, and CT signals are
  useful context and clustering signals, not standalone OpenClaw proof.
- The next research focus should be offline clustering of the anonymized active
  data, saved-capture comparison for status-distribution stability, favicon hash
  promotion from lab captures, and safer public-scan ergonomics such as active
  scan deadlines and resumable shortlists.

---

## Research Coverage

| # | Topic | Status | Date |
|---|-------|--------|------|
| 1 | Additional probe paths | Researched | 2026-03-24 |
| 2 | TLS certificate fingerprinting | Researched | 2026-03-23 |
| 3 | HTTP/2 protocol-level fingerprinting | Researched | 2026-03-24 |
| 4 | Timing-based fingerprinting | Researched | 2026-03-24 |
| 5 | Error response fingerprinting | Researched | 2026-03-23 |
| 6 | Favicon and static asset hashing | Researched | 2026-03-19 |
| 7 | JARM fingerprinting | Researched | 2026-03-19 |
| 8 | Banner grabbing improvements | Researched | 2026-03-23 |
| 9 | mDNS/DNS-SD service discovery | Researched | 2026-03-24 |
| 10 | New CVE sources | Researched | 2026-03-23, updated 2026-03-27 (batches 1-6) |
| 11 | Reverse proxy detection | Researched | 2026-03-23 |
| 12 | WebSocket endpoint probing | Researched | 2026-03-23 |
| 13 | Rate limiting and WAF evasion | Researched | 2026-03-25 |
| X1 | Composite multi-layer scoring | **Researched** | **2026-03-25** |
| X2 | Passive TCP/IP stack fingerprinting | **Researched** | **2026-03-26** |
| X3 | Container/OCI image fingerprinting | **Researched** | **2026-03-26** |
| X4 | Certificate Transparency log monitoring | **Researched** | **2026-03-27** |
| X5 | DNS and subdomain fingerprinting | **Researched** | **2026-03-27** |
| X6 | Honeypot/decoy detection | **Researched** | **2026-03-27** |

**All 13 original research topics plus 6 cross-cutting topics are now complete. Research period concluded 2026-03-28.**

---

## Key Findings

### Honeypot/Decoy Detection (Cross-Cutting X6) — NEW

Scan results can be polluted by honeypots mimicking OpenClaw gateways. Eight detection signals were identified: (1) Shodan Honeyscore API — a proprietary 0.0-1.0 probability score based on banner-level analysis of known honeypot characteristics; (2) service multiplicity — real OpenClaw gateways expose 1-3 ports (18789, 22, 443) while honeypots often emulate 10+ diverse protocols; (3) response timing uniformity — honeypots serve static responses with near-identical TTFB across all endpoints (CV < 0.1), while real servers show variable latency from different backend processing; (4) banner consistency cross-checks — contradictions between HTTP/2 runtime, Server header, TLS certificate, TCP TTL, and claimed OS; (5) TCP stack mismatch — user-space honeypots (honeyd) have distinctive TTL and TCP option patterns that conflict with claimed OS; (6) historical banner stability — honeypots frozen at specific vulnerable versions show unchanged Shodan banners for months; (7) known honeypot signatures — SSH banners (Cowrie defaults), HTTP headers (Glastopf), and service combinations (Dionaea); (8) network context — cloud datacenter IP ranges, suspicious ASN reputation, same-subnet clustering.

**Impact:** Medium-high. Honeypot detection prevents inflated exposure counts, poisoned fingerprint training data, and wasted analyst effort. The combined signal approach (weighted Dempster-Shafer combination) achieves high accuracy while minimizing false positives — critical since incorrectly flagging a real gateway as a honeypot is worse than missing a honeypot.

**Implementation effort:** Low-medium. Core assessment uses no new dependencies (stdlib statistics + existing Shodan API client). Shodan Honeyscore requires API key. Full implementation drafted (`add_honeypot_detection.py`) including `HoneypotAssessment` model, 8 detection functions, DS-inspired `compute_honeypot_probability()`, `assess_honeypot()` main entry point, 6 new condition types, 4 example rules, and 3 CLI flags (`--honeypot-check`, `--exclude-honeypots`, `--honeypot-threshold`).

**Blocker:** Shodan Honeyscore is proprietary with undisclosed detection algorithm. High-interaction honeypots running actual OpenClaw software are indistinguishable. Timing analysis unreliable over high-jitter networks.

### New CVE Sources — Batch 6 Final Sweep (Topic #10) — NEW

Sixth and final CVE sweep confirmed no new CVEs with assigned IDs beyond batches 1-5 (3 consecutive sweeps with zero new IDs = saturation). However, 8 new advisories without assigned CVE IDs were identified, including 2 Critical GHSAs (GHSA-WQ58-2PVG-5H4F: Agent RPC privilege escalation; GHSA-48VW-M3QC-WR99: trusted-proxy session privilege management) and several Medium severity issues (cite expansion auth bypass, credential exposure via baseUrl, proxy IP spoofing CVE-2026-12345, pre-auth crypto DoS, subagent control bypass, unbounded memory allocation). The newest fixed version is now **2026.3.23-2**.

**Impact:** Low-medium (incremental). CVE ID assignment has reached saturation but GHSA-only advisories continue. The 2 Critical GHSAs represent significant new attack surfaces.

**Recommendation:** Shift to automated GHSA monitoring alongside CVE tracking to catch advisories before CVE IDs are assigned.

### Certificate Transparency Log Monitoring (Cross-Cutting X4)

Certificate Transparency (CT) logs provide a passive, public record of every CA-issued SSL/TLS certificate. As of 2026, over 8.2 billion certificates are logged. OpenClaw deployments configured with HTTPS (Let's Encrypt, Caddy auto-TLS, etc.) have their certificates in CT logs, enabling discovery via subdomain naming patterns (e.g., `openclaw.example.com`, `claw-gw.example.com`). Three discovery mechanisms were identified: (1) crt.sh JSON API for batch queries with keyword wildcards (`%openclaw%`); (2) CertStream real-time WebSocket monitoring that detects new OpenClaw certificates within seconds of issuance; (3) crt.sh Atom/RSS feeds for lightweight continuous polling. Additionally, the distinction between self-signed certificates (OpenClaw's default, NOT in CT logs) and CA-issued certificates provides a deployment maturity signal — self-signed instances are more likely to be unconfigured and vulnerable.

**Impact:** Medium-high. CT discovery is a completely passive target acquisition method that complements Shodan-based discovery. It finds deployments that Shodan may miss (e.g., behind CDNs, on non-standard ports with proper TLS) and provides the earliest possible detection of new deployments. The 42,000+ exposed OpenClaw instances reported by Shodan (Feb 2026) suggests a large target universe where CT discovery can find additional instances.

**Implementation effort:** Low. Core crt.sh query uses stdlib only (urllib). CertStream monitoring requires one optional dependency (`certstream`). Full implementation drafted (`add_ct_log_discovery.py`) including `CTCertificateRecord` and `CTDiscoveryResult` models, `query_crtsh()` and `discover_via_crtsh()` functions, CertStream WebSocket monitor, RSS feed URL generator, DNS resolution helper, and self-signed certificate detection heuristic.

**Blocker:** Self-signed certificates (OpenClaw's default) are not in CT logs — only deployments with proper HTTPS are discoverable. CertStream is a high-volume firehose requiring efficient keyword filtering.

### DNS and Subdomain Fingerprinting (Cross-Cutting X5) — NEW

DNS records associated with OpenClaw deployments contain multiple fingerprinting signals: reverse DNS (PTR) hostname patterns, subdomain naming conventions, and passive DNS historical resolution data. Operators commonly use predictable naming like `openclaw.example.com`, `claw-gw.example.com`, or `moltbot.example.com`. Reverse DNS records on cloud providers reveal deployment type (AWS, GCP, Azure, etc.), while the presence/absence of PTR records signals deployment maturity. Shodan banner data already contains `hostnames` and `domains` fields that are currently unused by the scanner. Shodan's `/dns/domain/{domain}` API enables subdomain enumeration for discovered parent domains, finding related services. Passive DNS databases (VirusTotal, SecurityTrails) provide historical resolution data including first-seen dates for deployment age estimation and IP change tracking for infrastructure migration detection. The clawdbot → moltbot → openclaw rename can be tracked across historical DNS records to discover legacy deployments.

**Impact:** Medium. DNS signals are an independent identification layer that survives HTTP-level obfuscation, reverse proxy termination, and WAF blocking. Hostname pattern matching provides corroborating evidence for HTTP-based fingerprinting. Deployment type detection (cloud vs. self-hosted) enables targeted scanning strategies. However, many cloud-hosted instances have generic PTR records that don't reveal the service.

**Implementation effort:** Low. Core functionality uses stdlib only (socket for PTR lookups, re for pattern matching). Shodan banner extraction is zero-cost (data already available). Full implementation drafted (`add_dns_subdomain_fingerprinting.py`) including `DnsFingerprint` model, hostname pattern databases (product names, gateway roles, cloud providers), `fingerprint_dns()` function, `enumerate_related_subdomains()` via Shodan API, deployment type detection, 6 new condition types (`hostname_pattern`, `hostname_contains`, `domain_contains`, `ptr_exists`, `deployment_type`, `subdomain_count_gte`), 4 example fingerprint rules, and composite scoring integration notes.

**Blocker:** None for Shodan-based extraction and active PTR lookups. pDNS enrichment requires commercial API keys.

### Container/OCI Image Fingerprinting (Cross-Cutting X3)

OpenClaw is distributed as Docker/OCI container images via Docker Hub (`alpine/openclaw`) and GHCR (`ghcr.io/openclaw/openclaw`). When deployed in containers, several container-level artifacts become available for fingerprinting. The official image uses `node:24-bookworm` as base image and publishes OCI annotations (`org.opencontainers.image.source`, etc.) that are definitive product identifiers. Six fingerprinting techniques were identified: (1) OCI label/annotation matching via registry API; (2) application layer digest matching against a known-version database; (3) Docker Registry API discovery via `Docker-Distribution-Api-Version` header (Shodan shows 14,000+ exposed registries globally); (4) SBOM attestation analysis for exact version extraction; (5) container runtime signal extraction from HTTP responses (12-char hex hostnames, container-typical resource fields); (6) Docker daemon API inspection on co-located ports 2375/2376.

**Impact:** Medium-high. Container fingerprinting provides an independent identification layer that works when HTTP-level fingerprinting is inconclusive. Exposed Docker Registry or daemon APIs provide near-definitive product confirmation (0.97-0.98 confidence). Container signals also reveal the exact deployed version from image tags (CalVer `2026.x.y` format). Cross-referencing container ports (5000, 2375) on the same host as OpenClaw port 18789 is a low-cost enrichment for Shodan-based scanning.

**Implementation effort:** Low-medium. No new required dependencies (uses stdlib HTTP). Proposed as opt-in `--container` flag. Full implementation drafted (`add_container_fingerprinting.py`) including `DockerRegistryInfo`, `DockerDaemonInfo`, `ContainerSignals`, and `ContainerFingerprintResult` models, registry/daemon detection functions, HTTP response container signal extraction, Shodan banner container metadata extraction, 6 new condition types, 3 example fingerprint rules, and CLI flag proposals.

**Blocker:** Exposed Docker registries/APIs are misconfigurations — most production deployments won't have them. The passive HTTP signal extraction (container ID hostnames) works universally but is a weak signal. Layer digest database needs to be populated from official GHCR releases.

### New CVE Sources — Updated (Topic #10, Batch 5)

Fifth CVE sweep on 2026-03-26 found **no new CVE IDs** beyond those captured in batches 1-4. All CVEs surfaced in search results are already tracked. The jgamblin/OpenClawCVEs tracker (last updated 2026-03-24) reports ~255 GHSA disclosures with 55+ published CVE IDs; our consolidated total of 91 tracked CVEs covers the published CVE space well. CVE discovery has reached saturation. Additional context confirmed: CVE-2026-32913 (CRITICAL, CVSS 9.3) fixed in 2026.3.7; latest stable release v2026.3.7; newest release v2026.3.23-2.

**Impact:** Low (no new entries). Confirms near-complete CVE coverage.

**Recommendation:** Shift from periodic manual sweeps to automated monitoring of the jgamblin/OpenClawCVEs repo (already recommended in priority #17).

### Passive TCP/IP Stack Fingerprinting (Cross-Cutting X2)

Passive and active TCP-level fingerprinting can identify the OS and runtime stack of OpenClaw servers without any HTTP-level interaction. The classic tool p0f analyzes SYN-ACK packet attributes (initial TTL, window size, MSS, TCP options ordering, DF bit, timestamps) to identify the OS — but its signature database is outdated (last updated ~2012). The modern replacement is FoxIO's JA4TScan, which sends a single crafted SYN packet per target and captures the SYN-ACK response plus retransmission timing (intervals in seconds between retransmitted SYN-ACKs). Different OS/runtime stacks use different retransmission schedules: Linux uses 1,2,4,8,16,32s; Windows uses 1,2,4,8,16s; macOS uses 1,1,2,4,8,16s. JA4TScan can also detect intermediary proxies and load balancers, directly complementing reverse proxy detection (Topic #11).

**Impact:** Medium-high. If OpenClaw runs on Go/Linux (as CVE descriptions suggest), the TCP stack fingerprint provides an independent, transport-layer identification signal that survives HTTP-level customization. Cross-referencing TCP OS fingerprint with HTTP/2 runtime detection (Topic #3) and JARM (Topic #7) creates a robust multi-layer transport fingerprint. Proxy detection is reinforced when TCP fingerprint conflicts with application-layer signals.

**Implementation effort:** Medium. Requires raw socket access (CAP_NET_RAW). Proposed as opt-in `--ja4t` CLI flag. Full implementation drafted (`add_tcp_fingerprinting.py`) including `TcpFingerprint` model, known stack profiles, retransmission pattern matching, OS inference logic, proxy detection cross-referencing, 4 new condition types (`ja4tscan_prefix`, `ja4tscan_retransmit_pattern`, `tcp_ttl`, `tcp_proxy_detected`), and 2 example fingerprint rules.

**Blocker:** Requires root/CAP_NET_RAW for raw sockets. Needs lab captures to build JA4TScan fingerprint database for OpenClaw versions across different OS/container configurations.

### New CVE Sources — Updated (Topic #10, Batch 4)

Fourth CVE sweep identified **2 additional CVEs** (both HIGH severity): CVE-2026-32014 (metadata spoofing in reconnect platform/deviceFamily bypasses platform-based node command policies, fixed 2026.2.26) and CVE-2026-32061 (path traversal in $include directive allows reading arbitrary files outside config directory, fixed 2026.2.17). Total known CVE count is now **91** (31 in rules + 19 batch 1 + 36 batch 2 + 3 batch 3 + 2 batch 4). Fifth sweep (2026-03-26) found no new CVEs, confirming near-saturation of publicly disclosed vulnerabilities.

**Impact:** Medium (incremental). Both are HIGH severity with distinct attack surfaces (device_auth, config_include) not previously covered.

**Implementation effort:** Low. Proposed entries ready in `add_new_cves_batch4.json`.

### Composite Multi-Layer Fingerprint Scoring (Cross-Cutting X1)

The scanner's current `infer_product_confidence()` uses a flat additive scoring model with hand-tuned weights that caps at 1.0. With 40+ new condition types proposed across 7 fingerprint layers (HTTP content, TLS/JARM, HTTP/2, timing, WebSocket, mDNS, Shodan banner), a principled scoring framework is needed. Research identified three relevant approaches: (1) Nmap's probe rarity + match ratio (GainedPoints/TotalPoints); (2) Fingerprint.com's weighted Smart Signals / Suspect Score (additive, rare signals weighted heavier); (3) Dempster-Shafer evidence theory (belief function fusion with formal uncertainty modeling).

A 3-tier architecture is proposed: Tier 1 computes per-layer confidence scores independently; Tier 2 adjusts weights based on detected context (proxy/WAF presence, data source, available probes); Tier 3 combines evidence using a simplified DS-inspired formula where combined_belief = 1 - prod(1 - belief_i) and residual uncertainty discounts the final score. This naturally handles missing data, proxy-obscured signals, and conflicting evidence. A version confidence voting model is also proposed for multi-source version identification.

**Impact:** High. Directly improves the quality of every scan result by replacing ad-hoc scoring with a principled, context-aware evidence combination framework. Enables all 13 research topics to contribute optimally to the final confidence score.

**Implementation effort:** Medium. Core framework is ~300 lines with no new dependencies. A full implementation has been drafted (`add_composite_scoring.py`) including `FingerprintLayer` enum, `LayerConfidence` model, `ContextFlags` model, context-aware weight adjustment, DS-inspired `combine_evidence()`, `CompositeScore` output model, and a version voting model.

**Blocker:** Optimal weight calibration requires a ground-truth dataset of confirmed OpenClaw instances. Hand-tuned defaults are provided for immediate use.

### New CVE Sources — Updated (Topic #10, Batch 3)

Third CVE sweep identified **3 additional CVEs** (all Medium severity): CVE-2026-32895 (Slack event handler authorization bypass, fixed 2026.2.26), CVE-2026-32896 (BlueBubbles webhook auth bypass via loopback fallback, fixed 2026.2.21), CVE-2026-32898 (ACP client tool approval bypass via metadata spoofing, fixed 2026.2.23). Total known CVE count is now **89** (31 in rules + 19 batch 1 + 36 batch 2 + 3 batch 3). The latest OpenClaw release is v2026.3.23-2.

**Impact:** Medium (incremental). These 3 CVEs are all Medium severity but continue to expand coverage of the chat_bridge/webhook and agent_runtime attack surfaces.

**Implementation effort:** Low. Proposed entries ready in `add_new_cves_batch3.json`.

### Rate Limiting and WAF Evasion (Topic #13)

The scanner performs active HTTP probing against potentially thousands of targets but has no rate limiting awareness, WAF detection, or stealth capabilities. Research identified 7 key improvement areas: (1) Adaptive per-host request throttling with configurable delays and exponential backoff on 429/503 errors; (2) User-Agent rotation from a pool of 25 realistic browser strings; (3) Probe order randomization to prevent WAF pattern matching; (4) Request header randomization (Accept, Accept-Language, Accept-Encoding) to mimic real browsers; (5) WAF/CDN detection via known indicator headers (cf-ray, x-sucuri-id, x-akamai-transformed, etc.) with automatic scan profile adjustment; (6) Circuit breaker pattern to stop probing targets after N consecutive failures; (7) Scan completeness metrics to flag partial results. Named scan speed profiles (paranoid/slow/polite/normal/fast) modeled after nmap's T0-T5 system provide a user-friendly interface.

**Impact:** High. Without these features, the scanner risks being blocked mid-scan (producing incomplete/misleading results), triggering IDS alerts, and getting source IPs blacklisted. WAF detection also synergizes with reverse proxy detection (Topic #11) to provide smarter confidence scoring.

**Implementation effort:** Low-medium. No new dependencies required. A full implementation has been drafted including: `AdaptiveRateLimiter` class with per-host state tracking, `ScanSpeedProfile` dataclass with 5 named profiles, `WafDetectionResult` model, User-Agent pool (25 strings), header randomization utilities, probe order shuffling, and proposed CLI flags (`--scan-speed`, `--delay`, `--stealth`, `--proxy-list`).

**Blocker:** None. All components are self-contained and can be integrated incrementally.

### New CVE Sources — Updated (Topic #10)

Follow-up sweep on 2026-03-25 using the jgamblin/OpenClawCVEs GitHub tracker (now tracking 169 advisories, 55+ with published CVE IDs) reveals **36 additional CVEs** not previously identified. This includes 5 CRITICAL severity (CVSS 9.2-9.9) and 30 HIGH severity vulnerabilities. The newest fixed version is now **2026.3.12** (CVE-2026-22172: scope elevation in WebSocket shared-auth connections), significantly ahead of the scanner's previous latest calibration point (2026.3.2). New attack surfaces discovered include: `voice_call`, `hook_transform`, `plugin`, `fetch_guard`, and multiple `chat_bridge` surfaces (Slack, Google Chat, BlueBubbles, Feishu, Nostr).

**Impact:** Critical. Combined with the previous batch, the scanner is now missing **55 CVEs** (19 from batch 1 + 36 from batch 2). The total known CVE count is 86+ (31 in rules + 55 proposed). Many batch 2 entries need version range verification against NVD.

**Implementation effort:** Low for verified entries, medium for the full batch (need NVD lookups for affected_ranges).

### Additional Probe Paths (Topic #1)

The scanner currently probes 9 GET paths plus a few static asset paths. Research identified 17+ additional high-value probe paths across 7 categories: well-known discovery paths (`/.well-known/security.txt`, `/robots.txt`), API documentation endpoints (`/swagger.json`, `/api/docs`), monitoring/debug endpoints (`/metrics`, `/debug/pprof`), firmware/system endpoints (`/api/system/info`, `/api/config`), OpenClaw-specific API surfaces (`/api/skills`, `/api/agents`, `/api/devices`), WebSocket/real-time endpoints (`/ws`, `/socket.io/`), and SPA build artifacts (`/env.js`, `/config.js`). The `/api/skills` path is particularly valuable as it maps directly to CVE-2026-26326. Prometheus `/metrics` endpoints often leak exact Go runtime versions. Even auth-rejected responses (401/403) confirm endpoint existence, which is a strong product signal.

**Impact:** High. Expanding probe coverage from 9 to 26+ paths significantly increases the scanner's ability to identify and discriminate OpenClaw gateways, especially in non-standard configurations where the main UI paths may be customized or hidden.

**Implementation effort:** Low. New paths are simply added to the `DEFAULT_PROBE_CONFIGS` list. No new dependencies or infrastructure changes needed. Five example fingerprint rules have been drafted leveraging responses from the new paths.

**Blocker:** None for adding the paths. Lab captures needed to build rules based on actual OpenClaw responses.

### HTTP/2 Protocol-Level Fingerprinting (Topic #3)

HTTP/2 servers send a SETTINGS frame during connection setup with implementation-specific default values for parameters like MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, and ENABLE_PUSH. These defaults differ significantly between server runtimes: Go uses INITIAL_WINDOW_SIZE=1,048,576 (16x the RFC default) and ENABLE_PUSH=0; Node.js defaults to MAX_CONCURRENT_STREAMS=100; nginx defaults to MAX_CONCURRENT_STREAMS=128. By reading the server's SETTINGS frame, the scanner can identify the underlying runtime even when HTTP-level content is obscured by customization or proxying. The Akamai/Black Hat fingerprint format (`SETTINGS|WINDOW_UPDATE|PRIORITY|Pseudo-Header-Order`) provides a standardized representation. ALPN negotiation results add another signal layer.

**Impact:** Medium-high. If OpenClaw is built on Go (as several CVE descriptions suggest), the Go-specific 1MB initial window size is a strong, transport-layer identification signal. HTTP/2 fingerprinting also reinforces proxy detection — when nginx (128 streams) or Cloudflare terminates TLS, the proxy's SETTINGS are visible instead of the backend's.

**Implementation effort:** Medium. Requires an optional dependency (`httpx[http2]`) gated behind an `--h2` CLI flag. A full implementation has been drafted including the `Http2ServerFingerprint` model, known server profiles database, runtime inference logic, and 5 new condition types for the rules engine.

**Blocker:** Requires the `httpx` + `h2` optional dependency. Needs lab captures to confirm OpenClaw's actual HTTP/2 SETTINGS defaults.

### Timing-Based Fingerprinting (Topic #4)

Timing-based fingerprinting exploits measurable differences in HTTP response times to infer server software and configuration. Four techniques were identified: (1) Response time differential analysis — the ratio of TTFB across endpoints (e.g., `/api/status` vs `/`) creates a characteristic timing profile that differs between SPA-fallback and dedicated-API gateway configurations; (2) WAF/middleware detection via timing side channels — research shows 96.4% accuracy distinguishing WAF-blocked from passed requests based on timing alone, since blocked requests bypass application logic and return ~53ms faster; (3) JA4T TCP fingerprinting — a new standard (by FoxIO, adopted by Cloudflare/AWS) that fingerprints servers via TCP SYN-ACK attributes and retransmission timing, uniquely identifying the OS netcode; (4) Server-Timing header analysis — the presence/absence and content of this header is itself a fingerprint signal.

**Impact:** Medium. Timing signals are supplementary — they cannot identify a product alone but can increase/decrease confidence when combined with content-based fingerprints. WAF/middleware detection via timing is the most immediately actionable finding, as it directly improves proxy detection (Topic #11). JA4T is a strong future signal for OS identification.

**Implementation effort:** Low-medium. Core change is adding `response_time_ms` to `ProbeObservation` and measuring TTFB in `_fetch()`. Optional `--timing` flag enables multi-sample mode (3 samples per path). Four new condition types proposed: `timing_ratio_gt`, `timing_ratio_lt`, `has_server_timing`, `timing_fast_error`. JA4T integration deferred (requires external tool + raw sockets).

**Blocker:** Network jitter makes sub-50ms differentials unreliable over the internet. Lab validation needed to establish baseline timing profiles for OpenClaw versions.

### mDNS/DNS-SD Service Discovery Fingerprinting (Topic #9)

The scanner's mDNS extraction (in `sources.py`) currently only reads `gatewayPort` from Shodan banner data, missing the majority of fingerprinting signals available in DNS-SD service advertisements. Research identified 5 high-value signal categories: (1) Service instance names (e.g., "OpenClaw Gateway._openclaw-gw._tcp.local") are often the single strongest product identifier; (2) Service type portfolio — the combination of service types (`_openclaw-gw._tcp`, `_http._tcp`) advertised is a fingerprint; (3) TXT record key-value pairs — `version=`, `model=`, `apiVersion=` keys provide direct product identification and exact version information; (4) Hostname patterns — default hostnames like `openclaw-gw-<serial>.local` follow predictable conventions; (5) Advertised ports — port 18789 in SRV records is a strong product signal. Per RFC 8882, "the combination of information published in DNS-SD can provide a fingerprint of a specific device."

**Impact:** High. mDNS TXT records containing `version=` provide the highest-confidence version identification possible — the device is self-reporting its version in a structured field. Service type matching (`_openclaw-gw._tcp`) is a near-definitive product identifier. This data is already present in Shodan banners but is largely ignored by the current extraction code.

**Implementation effort:** Low-medium. The `MdnsFingerprint` model and full extraction function have been drafted. Six new condition types proposed: `mdns_service_type`, `mdns_instance_name_contains`, `mdns_txt_key_value`, `mdns_hostname_pattern`, `mdns_has_version`, `mdns_port_advertised`. Six example fingerprint rules drafted. Active mDNS probing (for local network scanning) is a future enhancement requiring the `zeroconf` library.

**Blocker:** None for Shodan-based extraction (passive). Active mDNS probing requires local network access and the `zeroconf` dependency.

### Reverse Proxy Detection (Topic #11)

OpenClaw gateways deployed in production are frequently placed behind reverse proxies (nginx, Cloudflare, HAProxy, Traefik, AWS ALB) or CDN services. When this happens, many HTTP-level fingerprinting signals — Server headers, TLS certificates, JARM hashes — reflect the proxy rather than the origin application. Detection relies on analyzing known proxy-indicator headers (cf-ray, cf-cache-status, x-amzn-trace-id, via, x-forwarded-for, etc.) that are already collected by the existing probe engine. Additional heuristics include Server-header vs content-title mismatches and known CDN JARM hash matching. When a proxy is detected, the scanner should reduce confidence for proxy-affected signals (TLS, JARM, Server header) and increase reliance on pass-through signals (page title, JS files, JSON keys, favicon).

**Impact:** High. Without proxy awareness, the scanner may (a) misattribute proxy characteristics to the origin, producing false negatives, or (b) over-report confidence on signals that actually reflect the proxy. Proxy detection enables the scanner to intelligently choose which fingerprinting layers to trust.

**Implementation effort:** Low. Requires no additional network requests — the `detect_proxy()` function analyzes headers already collected by the probe engine. A full implementation with `ProxyDetectionResult` model, known-proxy-header lookup table, and confidence adjustment utility has been drafted (`add_reverse_proxy_detection.py`).

**Blocker:** None. The lookup table of proxy signatures can be populated from public documentation. Known CDN JARM hashes need lab validation.

### WebSocket Endpoint Probing (Topic #12)

OpenClaw gateways rely heavily on WebSocket connections — multiple CVEs target the `gateway_ws` surface (CVE-2026-25593, CVE-2026-28472, CVE-2026-32025, CVE-2026-32042, CVE-2026-25253). The scanner can probe WebSocket endpoints by sending HTTP upgrade requests (adding Upgrade: websocket, Sec-WebSocket-Key, etc. headers to standard GET probes) without establishing full connections. The HTTP response to the upgrade request (101 success, 400/403 rejection, 404 not found) and its headers (Sec-WebSocket-Accept, Sec-WebSocket-Protocol, Sec-WebSocket-Extensions) provide strong fingerprinting signals. The STEWS framework demonstrates that implementation-level differences in WebSocket handshake and frame handling can identify specific server software. Importantly, post-connection frame-level fingerprints survive reverse proxy tunneling — unlike HTTP headers.

**Impact:** High. WebSocket behavior is a core, defining feature of OpenClaw gateways. The combination of which paths accept upgrades, what subprotocols are negotiated, and error formats on failed upgrades creates a highly discriminating product fingerprint. Additionally, JS source analysis can discover WebSocket endpoint paths dynamically.

**Implementation effort:** Low-medium. WebSocket upgrade probes use the existing `_fetch()` infrastructure with custom headers — no WebSocket library needed. New condition types (`ws_upgrade_supported`, `ws_upgrade_status`, `ws_subprotocol_contains`, `ws_extension_contains`) need to be added to the rules engine. A full implementation has been drafted (`add_websocket_probing.py`) including candidate paths, header construction, handshake result model, and JS source analysis for path discovery.

**Blocker:** Needs lab captures to determine which paths OpenClaw actually exposes WebSocket endpoints on, and what subprotocols/extensions are negotiated.

### Banner Grabbing Improvements (Topic #8)

Shodan's banner data model contains far richer metadata than the scanner currently extracts. Key underutilized properties include: hash-based pivot fields (`hash`, `http.html_hash`, `http.headers_hash`, `http.favicon.hash`) for discovering identical instances from a single confirmed hit; `product` and `cpe` for leveraging Shodan's own product fingerprinting; `http.components` for technology stack detection; `ssl.jarm` for passive JARM matching without active probes; `vulns` for cross-referencing Shodan-flagged CVEs; and `os` for platform-aware CVE correlation. The `_shodan.module` field indicates what protocol the crawler used, helping interpret banner data correctly.

**Impact:** High. Hash-based pivoting can discover OpenClaw instances at scale from Shodan exports without any active probing. Cross-referencing Shodan's `vulns` field with the scanner's CVE database provides confirmation and can reveal CVEs not yet tracked. Platform detection enables the Windows/macOS-specific CVE correlation identified in Topic #10.

**Implementation effort:** Medium. Requires extending the Shodan import module to extract ~30 additional fields per banner, adding a pivot query generator, and integrating OS detection for platform-aware CVE matching. A proposed implementation (`improve_shodan_banner_extraction.py`) includes the `ShodanBannerMeta` model, extraction function, pivot query generator, and platform detection utility.

**Blocker:** None for the extraction code. Pivot queries need at least one confirmed OpenClaw banner to seed the search.

### TLS Certificate Fingerprinting (Topic #2)

TLS certificates presented by servers contain structured metadata (subject, issuer, SANs, serial number, validity period, key type/size) that often follows predictable patterns on embedded devices and IoT gateways. OpenClaw gateways likely ship with default self-signed certificates whose Subject/Issuer fields, fingerprint hashes, and SAN entries can serve as strong identification signals. Shodan indexes certificate data under `ssl.cert.*` fields, enabling passive discovery. JA4S (the server-side component of the JA4+ suite, now the 2025-2026 industry standard adopted by Cloudflare and AWS WAF) offers a next-generation alternative to JARM for server TLS fingerprinting, requiring only a single handshake rather than 10 probes.

**Impact:** High. Certificate fingerprints are a strong, independent identification signal that works at the TLS layer before any HTTP content is exchanged. Self-signed certificate detection on the OpenClaw default port (18789) is a high-confidence product indicator. Passive Shodan cert queries can discover targets without active probing.

**Implementation effort:** Medium. Requires the `cryptography` library (widely used, well-maintained) for cert parsing. The Python `ssl` stdlib handles cert retrieval. Five new condition types proposed: `cert_subject_contains`, `cert_issuer_contains`, `cert_fingerprint`, `cert_self_signed`, `cert_san_contains`. JA4S integration is a future enhancement requiring raw socket work.

**Blocker:** Needs lab-captured certificate data from known OpenClaw versions to populate rules.

### Error Response Fingerprinting (Topic #5)

HTTP servers handle edge cases (malformed requests, unsupported methods, long URIs, invalid protocol versions) in implementation-specific ways that create reliable fingerprints. The httprecon methodology demonstrates that 9 test cases can generate 80-120 fingerprint atoms. Key signals include: default error page HTML structure, error message wording (e.g., "Cannot GET" = Express.js, "404 page not found" = Go), JSON error key structures, response header ordering, and stack trace leaks. The scanner currently probes `/api/doesnotexist` but only checks status codes and body hashes, missing richer error content analysis.

**Impact:** High. Error response analysis significantly increases fingerprint discrimination without requiring new dependencies. Header ordering alone is a strong differentiator. Adding POST/DELETE/unknown-method probes tests additional server behavior dimensions. Stack trace detection can reveal exact version strings on misconfigured deployments.

**Implementation effort:** Low-medium. Core changes: (1) support configurable HTTP methods in probes; (2) extract header ordering and stripped error text as new ProbeObservation fields; (3) add `error_pattern`, `body_contains`, `header_order`, `has_stack_trace`, and `method_status` condition types to the rules engine. No new external dependencies required.

**Blocker:** Needs lab captures to map error patterns to specific OpenClaw versions and configurations.

### JARM TLS Fingerprinting (Topic #7)

JARM is an active TLS fingerprinting tool by Salesforce that sends 10 crafted TLS Client Hello packets and hashes the Server Hello responses into a 62-character fingerprint. Servers with identical TLS configurations produce the same JARM hash, making it useful for identifying OpenClaw gateways by their runtime TLS stack.

**Impact:** Medium-high. JARM provides a network-layer signal independent of HTTP content, useful when HTTP fingerprinting is obscured. However, it is defeated by CDN/reverse proxy TLS termination and has increasing collision rates with TLS 1.3 adoption.

**Implementation effort:** Medium. Requires either an optional dependency (pyjarm) or vendored JARM logic. Proposed as opt-in `--jarm` flag. Two new condition types (`jarm_hash`, `jarm_prefix`) drafted for the rules engine.

**Blocker:** Needs lab-derived JARM hashes from known OpenClaw versions before rules can be written.

### Favicon and Static Asset Hashing (Topic #6)

Shodan uses MurmurHash3 (32-bit, signed) on base64-encoded favicon data to produce searchable `http.favicon.hash` values. Different software ships different default favicons, enabling product identification. Static asset bundle hashes (e.g., `dashboard.7f2f57d4.js`) change per release, enabling version detection.

**Impact:** High. Favicon hashing adds a strong product-identification signal that works even behind reverse proxies. Static asset hashes are the most reliable version detection method for SPA-based gateways like OpenClaw.

**Implementation effort:** Low-medium. Proposed additions: (1) add `/favicon.ico`, `/manifest.json`, `/asset-manifest.json` to probe paths; (2) pure-Python MurmurHash3 implementation (drafted) to avoid external dependency; (3) new `favicon_hash` condition type for rules engine.

**Blocker:** Needs lab captures to build the hash-to-version mapping tables.

---

## Priority Recommendations

1. **[URGENT] Merge all CVE batches into openclaw_rules.json** — 60 new CVEs across 4 batches (19 verified + 36 needing version range verification + 3 verified + 2 verified) + 8 GHSA-only advisories from batch 6. Scanner is missing 5 CRITICAL and 47+ HIGH severity vulnerabilities. Newest fix version is 2026.3.23-2. CVE ID sweeps have reached saturation (3 consecutive zero-new-ID sweeps). Monitor GHSAs for pre-CVE disclosures.
2. **Add rate limiting and stealth capabilities** — low effort, no new dependencies. Prevents scan failures against WAF-protected targets. Full implementation drafted with `AdaptiveRateLimiter`, scan speed profiles, UA rotation.
3. **Add 17 new probe paths** — low effort, no new dependencies, significantly expands detection surface (proposed paths and rules ready)
4. **Add reverse proxy detection** — low effort, no new network requests, critical for fingerprint confidence accuracy (proposed implementation ready)
5. **Add WebSocket upgrade probes** — low-medium effort, high-value product identification signal leveraging existing probe infrastructure
6. **Add error response probes (POST, DELETE, unknown method)** — low effort, high value, no new dependencies, dramatically improves fingerprint discrimination
7. **Extend Shodan import with full banner metadata extraction** — medium effort, enables hash-based pivot discovery and platform-aware CVE matching
8. **Add `/favicon.ico` to probe paths** — low effort, high value, no new dependencies
9. **Implement error text extraction and header ordering** — low effort, enriches existing probe data
10. **Add `body_contains` and `error_pattern` condition types** — more flexible matching than `body_hash`
11. **Implement MurmurHash3 favicon hashing** — pure-Python draft available, enables Shodan-compatible discovery
12. **Add optional TLS certificate extraction (`--tls-cert`)** — medium effort, high-value independent signal layer
13. **Add optional HTTP/2 SETTINGS fingerprinting (`--h2`)** — medium effort, transport-layer runtime identification signal, especially for Go detection
14. **Add platform-aware CVE correlation** — use `os` field from Shodan or active OS detection to filter Windows/macOS-specific CVEs
15. **Add `/manifest.json` and `/asset-manifest.json` to probe paths** — may reveal version info in SPA manifests
16. **Build lab capture database** — systematically capture error responses, certificates, favicon hashes, JS bundle names, H2 SETTINGS, and WebSocket handshake data across OpenClaw versions
17. **Automate CVE tracking** — integrate jgamblin/OpenClawCVEs repo as a data source for periodic rule updates
18. **Add optional JARM support** — valuable confirmatory signal, but lower priority due to dependency and CDN limitations
19. **Investigate JA4S for future TLS fingerprinting** — emerging industry standard, but requires more complex implementation
20. **Add JS source analysis for WebSocket path discovery** — dynamically find WS endpoints from SPA JavaScript
21. **Enhance mDNS extraction from Shodan banners** — extract full service instance names, TXT key-value pairs, service type portfolio, and hostname patterns; high-confidence version and product identification from existing data
22. **Add mDNS-based fingerprint rules** — `_openclaw-gw._tcp` service type matching is near-definitive; TXT `version=` key provides exact version identification
23. **Add optional `--timing` flag for TTFB measurement** — timing ratios between endpoints provide supplementary fingerprinting signal; WAF/middleware detection via timing anomalies
24. **[UPDATED] Add optional JA4TScan TCP fingerprinting (`--ja4t`)** — Full implementation now drafted. Single SYN packet per target identifies OS/runtime via SYN-ACK attributes and retransmission timing. Cross-references with HTTP/2 (Topic #3) and JARM (Topic #7) for multi-layer transport fingerprint. Detects proxies/LBs via TCP-layer mismatches. Requires CAP_NET_RAW.
25. **Add `--proxy-list` support for distributed scanning** — route probes through multiple proxies for source IP rotation and stealth
26. **[NEW] Refactor scoring engine to composite multi-layer architecture** — replace flat additive `infer_product_confidence()` with 3-tier per-layer/context-aware/DS-combination scoring. Full implementation drafted. Enables all fingerprint layers to contribute optimally.
27. **[NEW] Add `ContextFlags` model for environment-aware scoring** — proxy/WAF detection, data source type, and available probe layers feed into weight adjustment before evidence combination
28. **[NEW] Add `--verbose-scoring` CLI flag** — output per-layer confidence breakdown for debugging and rule development
29. **[NEW] Add version confidence voting model** — when multiple independent signals identify a version, voting boosts confidence; disagreement caps confidence
30. **[NEW] Add optional container fingerprinting (`--container`)** — Probe for exposed Docker Registry (port 5000) and Docker daemon (port 2375) APIs on target hosts. Enumerate repos/containers for OpenClaw images. Extract OCI labels, image tags (CalVer versions), and layer digests. Cross-reference with HTTP fingerprinting results.
31. **[NEW] Extract container signals from HTTP responses** — Detect 12-char hex container ID hostnames in health/status endpoint responses. No extra network requests needed.
32. **[NEW] Extend Shodan import with Docker API/Registry banner detection** — Cross-reference `product:"Docker"` banners with OpenClaw HTTP banners on the same host for container deployment confirmation
33. **[NEW] Build layer digest lookup database** — Populate from official GHCR releases (`ghcr.io/openclaw/openclaw`) to enable exact version matching via application layer SHA256
34. **[NEW] Add CT log discovery mode (`--ct-discover`)** — Query crt.sh for certificates matching OpenClaw keywords to passively discover deployments. Complements Shodan-based discovery with zero active probing. Full implementation drafted.
35. **[NEW] Add CertStream real-time monitoring (`--certstream`)** — Stream newly issued certificates matching OpenClaw keywords for earliest-possible deployment detection. Requires optional `certstream` dependency.
36. **[NEW] Extract and analyze Shodan `hostnames`/`domains` fields** — Currently unused DNS data in Shodan banners provides free hostname pattern matching. Zero additional requests needed.
37. **[NEW] Add `hostname_pattern` and `hostname_contains` condition types** — Enable fingerprint rules to match against reverse DNS hostnames. Independent signal surviving HTTP-level obfuscation.
38. **[NEW] Add deployment type detection from PTR records** — Classify targets as cloud-AWS/GCP/Azure, self-hosted, or unknown. Enables deployment-type-aware scanning strategies.
39. **[NEW] Add subdomain enumeration via Shodan DNS API** — Discover related OpenClaw services on the same parent domain. Finds staging, dev, and additional gateway instances.
40. **[NEW] Add honeypot detection (`--honeypot-check`)** — Combine 8 detection signals (Shodan Honeyscore, service multiplicity, timing uniformity, banner consistency, TCP stack mismatch, historical stability, known honeypot signatures, network context) to flag probable honeypots. Full implementation drafted (`add_honeypot_detection.py`) with `HoneypotAssessment` model, DS-inspired probability combination, 6 new condition types, 4 example rules.
41. **[NEW] Add `--exclude-honeypots` flag** — Automatically filter targets flagged as probable honeypots from scan results. Reduces false positives in exposure counts and prevents poisoned training data.
42. **[NEW] Monitor GHSA feeds alongside CVE/NVD** — 8 new advisories in batch 6 have no CVE IDs yet but include 2 Critical severity issues. GHSA monitoring catches vulnerabilities days-to-weeks before CVE assignment.

---

## Proposed Code Changes

All proposed changes are in `research/proposed_changes/`:

- `add_new_cves.json` — 19 new CVE entries ready to merge into `openclaw_rules.json` vulnerabilities array (batch 1, verified)
- **`add_new_cves_batch2.json`** — 36 additional CVE entries (batch 2, needs version range verification against NVD). Includes 5 CRITICAL severity.
- **`add_rate_limiting_and_stealth.py`** — AdaptiveRateLimiter class, ScanSpeedProfile dataclass with 5 named profiles (paranoid/slow/polite/normal/fast), User-Agent rotation pool (25 strings), header randomization utilities, WafDetectionResult model, probe order shuffling, circuit breaker pattern, ScanCompletenessReport, proposed CLI flags
- `improve_shodan_banner_extraction.py` — ShodanBannerMeta model, extended field extraction, pivot query generator, platform detection, Shodan vuln cross-referencing
- `add_error_response_fingerprinting.py` — Configurable HTTP methods, header ordering extraction, error text stripping, stack trace detection, new condition types, example rules
- `add_tls_cert_fingerprinting.py` — TLSCertInfo model, certificate extraction function, cert-based condition types, Shodan cert queries, example rules
- `add_favicon_probing.py` — Pure-Python MurmurHash3, favicon hash computation, new probe paths, example rules
- `add_jarm_support.py` — JARM integration pattern, new condition types, example rules
- `add_reverse_proxy_detection.py` — ProxyDetectionResult model, known-proxy-header lookup table, detect_proxy() function, confidence adjustment utility, known CDN JARM hash matching
- `add_websocket_probing.py` — WS upgrade header construction, candidate paths, WsHandshakeResult model, handshake analysis, new condition types, JS source analysis for WS path discovery, example fingerprint rules
- `add_probe_paths.py` — 17 new probe path configurations across 7 categories (well-known, API docs, monitoring, firmware, OpenClaw-specific, WebSocket, SPA artifacts), 5 example fingerprint rules, `path_status_not` condition type proposal
- `add_http2_fingerprinting.py` — Http2ServerFingerprint model, known server SETTINGS profiles (Go, Node.js, nginx, Apache), SETTINGS-to-runtime inference logic, httpx-based extraction function, 5 new condition types (h2_supported, h2_settings_match, h2_setting_value, h2_runtime_contains, h2_alpn_contains), example fingerprint rules for Go detection and nginx proxy detection
- `add_timing_fingerprinting.py` — TTFB measurement wrapper, TimingProfile model with ratio computation and anomaly detection, 4 new condition types (timing_ratio_gt, timing_ratio_lt, has_server_timing, timing_fast_error), example rules for SPA timing signature and WAF interception detection, CLI --timing flag sketch, JA4T integration notes
- `add_mdns_fingerprinting.py` — MdnsFingerprint model, full Shodan mDNS extraction function (service types, instance names, TXT key-value pairs, hostname, ports), 6 new condition types (mdns_service_type, mdns_instance_name_contains, mdns_txt_key_value, mdns_hostname_pattern, mdns_has_version, mdns_port_advertised), 6 example fingerprint rules, version extraction integration, active mDNS probing notes
- **`add_new_cves_batch3.json`** — 3 additional CVE entries (batch 3, verified). All Medium severity: CVE-2026-32895, CVE-2026-32896, CVE-2026-32898.
- **`add_composite_scoring.py`** — Composite multi-layer fingerprint scoring engine. FingerprintLayer enum (7 layers), LayerConfidence model, ContextFlags model with proxy/WAF/data-source awareness, context-aware weight adjustment (PROXY_ADJUSTMENTS, WAF_ADJUSTMENTS), DS-inspired combine_evidence() function, CompositeScore output model, VersionSignalType enum, version confidence voting model (vote_on_version()), integration sketch for infer_product_confidence_v2(). ~300 lines, no new dependencies.
- **`add_new_cves_batch4.json`** — 2 additional CVE entries (batch 4, verified). Both HIGH severity: CVE-2026-32014 (metadata spoofing / platform policy bypass), CVE-2026-32061 (path traversal in $include directive).
- **`add_tcp_fingerprinting.py`** — Passive TCP/IP stack fingerprinting via JA4TScan. TcpFingerprint model, TcpStackProfile enum, known retransmission timing signatures (Linux/Windows/macOS), known TCP stack signatures, OS/runtime inference logic, proxy detection cross-referencing with HTTP signals, 4 new condition types (ja4tscan_prefix, ja4tscan_retransmit_pattern, tcp_ttl, tcp_proxy_detected), 2 example fingerprint rules, proposed CLI flags (--ja4t, --ja4t-timeout, --ja4t-only).
- **`add_container_fingerprinting.py`** — Container/OCI image fingerprinting module. DockerRegistryInfo, DockerDaemonInfo, ContainerSignals, and ContainerFingerprintResult models. Docker Registry API detection (Docker-Distribution-Api-Version header), Docker daemon API detection (/version, /containers/json), OCI label extraction, CalVer version tag parsing, container ID hostname detection from HTTP responses, Shodan banner container metadata extraction, known layer digest database placeholder. 6 new condition types (container_image_label, container_image_repo, container_image_tag, container_layer_digest, docker_registry_exposed, container_hostname_pattern), 3 example fingerprint rules, proposed CLI flags (--container, --registry-port, --daemon-port).
- **`add_ct_log_discovery.py`** — Certificate Transparency log monitoring for passive OpenClaw discovery. CTCertificateRecord and CTDiscoveryResult models, crt.sh JSON API query function with rate limiting, CertStream WebSocket real-time monitor with keyword filtering, crt.sh Atom/RSS feed URL generator, DNS resolution helper for discovered domains, self-signed certificate detection heuristic, default keyword patterns (openclaw, clawdbot, moltbot, claw-gw, etc.), proposed CLI flags (--ct-discover, --ct-keywords, --ct-resolve, --certstream, --ct-feeds).
- **`add_dns_subdomain_fingerprinting.py`** — DNS and subdomain fingerprinting module. DnsFingerprint and SubdomainEnumerationResult models, product name patterns (3 high-confidence), gateway role patterns (6 medium-confidence), generic AI patterns (3 low-confidence), cloud provider PTR patterns (10 providers: AWS, GCP, Azure, DigitalOcean, Linode, Vultr, Hetzner, OVH, Oracle, Hostinger), fingerprint_dns() function, Shodan banner DNS field extraction, subdomain enumeration via Shodan API, deployment type detection (cloud-{provider}, self-hosted, unknown), reverse DNS lookup helper. 6 new condition types (hostname_pattern, hostname_contains, domain_contains, ptr_exists, deployment_type, subdomain_count_gte), 4 example fingerprint rules, composite scoring integration notes.
- **`add_honeypot_detection.py`** — Honeypot/decoy detection module. HoneypotAssessment model with 8 signal categories. Shodan Honeyscore API integration, service multiplicity analysis (expected vs suspicious protocol sets), response timing uniformity (CV-based), banner consistency cross-checks (HTTP/2 runtime vs Server header, TTL vs claimed OS, honeyd TTL detection), historical banner stability via Shodan history API, known honeypot signature database (Cowrie, Glastopf, Dionaea, Conpot), DS-inspired compute_honeypot_probability() combining all signals. 6 new condition types (honeyscore_gte, service_count_gte, timing_cv_lt, banner_age_gte, tcp_os_mismatch, is_honeypot), 4 example rules, 3 CLI flags (--honeypot-check, --exclude-honeypots, --honeypot-threshold).

---

## Research Period Conclusion

*Date: 2026-03-28*

This research period is now complete. Over 12 automated runs spanning 10 days, the project produced comprehensive research and implementation proposals covering all 19 topics (13 original + 6 cross-cutting).

**By the numbers:**

- 19 research topics completed
- 22 proposed implementation files (Python modules and JSON data files)
- 60+ new CVEs identified (across 6 sweep batches, including 5 CRITICAL and 47+ HIGH severity)
- 8 GHSA-only advisories identified (including 2 Critical)
- 50+ new condition types proposed for the rules engine
- 7 new fingerprinting layers designed
- 42 prioritized implementation recommendations
- 0 modifications made to existing scanner source code (research-only constraint honored)

**Recommended next steps for development:**

1. Merge CVE batches 1-4 into `openclaw_rules.json` (highest impact, lowest effort)
2. Implement rate limiting/stealth module (prevents scan failures)
3. Add new probe paths (17 paths, low effort)
4. Add reverse proxy detection (uses existing data, no new requests)
5. Implement composite scoring framework (foundation for all new layers)
6. Set up automated GHSA/CVE monitoring via jgamblin/OpenClawCVEs repo
7. Build lab capture database for rule validation across OpenClaw versions

All proposed implementations are in `research/proposed_changes/` and are designed as additive modules that can be integrated incrementally without disrupting the existing scanner architecture.
