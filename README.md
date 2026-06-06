<p align="center">
  <img src="assets/openclaw-scanner.png" alt="OpenClaw Scanner logo" width="360">
</p>

<h1 align="center">OpenClaw Scanner</h1>

<p align="center">
  <strong>Evidence. Not assumption.</strong><br>
  OpenClaw scanner for fingerprinting exposed OpenClaw gateways, including
  OpenClaw port 18789 scanner workflows and evidence-first OpenClaw
  vulnerability triage.
</p>

<p align="center">
  <img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white">
  <img alt="Stdlib only" src="https://img.shields.io/badge/dependencies-stdlib--only-0B7285">
  <img alt="License MIT" src="https://img.shields.io/badge/license-MIT-2F9E44">
  <img alt="Exact rules" src="https://img.shields.io/badge/exact_rules-17-E8590C">
  <img alt="Latest OpenClaw" src="https://img.shields.io/badge/latest_openclaw-2026.6.1-1864AB">
  <img alt="Evidence first" src="https://img.shields.io/badge/mode-evidence--first-C92A2A">
</p>

<p align="center">
  <strong>Authorized web checker:</strong>
  <a href="https://mahdihedhli.github.io/openclaw_scanner/checker/">OpenClaw Exposure Checker</a>
</p>

---

## Why This Exists

`openclaw_scanner` is an open source OpenClaw scanner that helps defenders
fingerprint exposed OpenClaw gateways without overclaiming. It supports
OpenClaw port 18789 scanner workflows, passive discovery from Shodan/Censys/
FOFA/CT exports, low-impact active validation, and conservative OpenClaw
vulnerability triage when correlation-grade exact version evidence is visible
from the network.

The scanner is intentionally low-impact. It does not exploit hosts, attempt
authentication bypasses, brute force credentials, or run intrusive payloads.
Use it only for systems you own or are explicitly authorized to assess. Active
scanning of internet-facing IPs you are not authorized to test is not supported
by this project.

## At A Glance

| Capability | What you get |
| --- | --- |
| 🔎 Passive discovery | Shodan query IDs, Shodan/Censys/FOFA/CT imports, mDNS parsing, hash pivots, confidence weights |
| 🌐 Active gateway probing | Low-impact default GET/WebSocket probes; conditional deep validation after strong family evidence |
| 🧬 Fingerprint evidence | Status distributions, titles, JS assets, favicon hashes, JSON key shapes, body markers, version hints |
| 🧪 Exact version rules | 17 lab-promoted OpenClaw releases through `2026.5.28` |
| 📦 Latest OpenClaw package | `2026.6.1` is published; exact-rule coverage still requires a lab capture before promotion |
| 🛡️ Defensive context | Reverse-proxy detection, honeypot heuristics, vulnerability correlation |
| 🐍 Portable runtime | Stock `python3`; no third-party Python dependencies |

## OpenClaw Scanner Search Phrases

This project intentionally covers the common defensive search intents:

- OpenClaw scanner
- fingerprint exposed OpenClaw gateways
- OpenClaw port 18789 scanner
- OpenClaw vulnerability triage
- OpenClaw gateway fingerprinting
- Clawdbot and Moltbot gateway exposure checks

## Quick Navigation

- [Quick Start](#quick-start)
- [Field Calibration Snapshot](#field-calibration-snapshot)
- [Public Exposure Checker](#public-exposure-checker)
- [Known-Version Corpus](#known-version-corpus)
- [Input Formats](#input-formats)
- [Black-Box Calibration Workflow](#black-box-calibration-workflow)
- [Custom Fingerprint Rules](#custom-fingerprint-rules)
- [Tests](#tests)

## What It Does

For each target, the scanner:

1. probes common OpenClaw gateway endpoints, OpenAI-compatible model paths,
   WebSocket upgrades, static assets, and safe error-behavior paths using
   default GET requests plus WebSocket upgrade-header handshakes only
2. records headers, header ordering, status codes, stripped error text, stack
   trace hints, titles, favicon hashes, JS asset paths, JSON key shapes,
   product markers, response timing, version hints, and
   `status_distribution_signature`
3. imports passive Shodan, Censys, FOFA, and CT metadata such as titles, TLS
   names, JARM values, favicon hashes, Shodan-reported CVEs, and structured
   mDNS gateway metadata when available
4. detects likely reverse proxies or WAF edges from live responses and passive
   Shodan WAF hints
5. applies conservative family fingerprint rules and exact-version rules
6. correlates inferred versions with the bundled OpenClaw vulnerability data

## Evidence Model

OpenClaw Scanner separates discovery, identification, version attribution, and
vulnerability correlation:

| Stage | Meaning | What it can drive |
| --- | --- | --- |
| Candidate | A passive source, query, CT name, title, favicon hash, TLS name, JARM value, or mDNS record suggests a host may be worth checking. | Triage and target selection only. |
| Active service signal | A live low-impact probe returns status, headers, title, JSON keys, body markers, static assets, or WebSocket handshake behavior. | Stronger triage and response clustering. |
| Family fingerprint | Multiple remote-visible signals match a bundled OpenClaw-family behavior rule. | Family-level identification and optional conditional deep validation. |
| Exact version evidence | A lab-promoted exact rule or explicit correlation-grade metadata such as mDNS `cliPath` package version matches. | Exact-version attribution. |
| Vulnerability correlation | A correlation-grade version match intersects bundled vulnerability ranges. | Defensive vulnerability triage, not exploitability proof. |

Passive discovery metadata does not equal version evidence. Passive datasets are
useful for finding candidates, but current field data shows they do not provide
reliable exact-version fingerprinting by themselves. CDP/Chromium signals are
browser-agent evidence; CDP alone is not standalone OpenClaw proof and never
drives vulnerability correlation.

## Quick Start

Scan a single target:

```bash
python3 -m openclaw_scanner --target https://127.0.0.1:18789 --format pretty
```

Scan a target list and write JSON:

```bash
python3 -m openclaw_scanner \
  --targets-file targets.txt \
  --format json \
  --output results.json
```

Analyze a Shodan export passively:

```bash
python3 -m openclaw_scanner \
  --shodan-file shodan-results.json \
  --format csv \
  --output triage.csv
```

Actively re-probe Shodan-derived candidates:

```bash
python3 -m openclaw_scanner \
  --shodan-file shodan-results.json \
  --rescan-shodan \
  --format json \
  --output active-results.json
```

Run a live Shodan query:

```bash
SHODAN_API_KEY=... python3 -m openclaw_scanner \
  --shodan-query 'product:"mDNS" "clawdbot-gw"' \
  --shodan-pages 2 \
  --format pretty
```

List built-in discovery queries and run one by ID:

```bash
python3 -m openclaw_scanner --list-discovery-queries

SHODAN_API_KEY=... python3 -m openclaw_scanner \
  --discovery-query shodan-title-openclaw-control \
  --shodan-pages 1 \
  --format csv
```

Import other passive datasets:

```bash
python3 -m openclaw_scanner \
  --censys-file censys-export.json \
  --fofa-file fofa-export.csv \
  --ct-file ct-export.jsonl \
  --format json
```

Probe likely gateways on alternate ports and use conditional deep validation:

```bash
python3 -m openclaw_scanner \
  --shodan-file shodan-results.json \
  --rescan-shodan \
  --probe-ports \
  --deep-validation \
  --format json
```

Export the next public-safe calibration targets from an anonymized active CSV:

```bash
python3 -m openclaw_scanner \
  --calibration-candidates-from artifacts/shodan/2026-06-03/public/openclaw-active-default-100-anonymized.csv \
  --format csv \
  --output next-calibration-candidates.csv
```

Use the bundled demo data:

```bash
python3 -m openclaw_scanner \
  --shodan-file openclaw_scanner/data/demo_18789-03-17-2026.json \
  --rescan-shodan \
  --format pretty
```

## Field Calibration Snapshot

OpenClaw Scanner now has two public-safe calibration passes that demonstrate
the value of separating discovery from identification.

### 2026-06-02 mDNS-oriented pass

The first public-facing calibration pass used anonymized data from 500 passive
Shodan rows and a 100-target active shortlist:

| Metric | Result |
| --- | ---: |
| Passive Shodan candidates | 500 |
| Active shortlist | 100 |
| Responsive active hosts | 14 |
| Active OpenClaw family matches | 13 |
| Exact version matches | 0 |
| Candidate-to-responsive rate | 14% |
| Candidate-to-family-match rate | 13% |
| Passive-to-family-match rate | 2.6% |

The active sample also produced clustered `status_distribution_signature`
values such as `200:13;401:1;404:23` and `200:13;401:3;404:21`.

### 2026-06-03 title-query follow-up

The follow-up pass used the expanded discovery query support against
`http.title:"OpenClaw Control"`, normalized 500 passive candidates, and actively
validated a 100-host shortlist twice: once in the default low-impact mode and
once with `--deep-validation` enabled but POST probes still disabled.

| Metric | Passive candidates | Active default | Active deep, no POST |
| --- | ---: | ---: | ---: |
| Results processed | 500 | 100 | 100 |
| Responsive active hosts | N/A | 100 | 100 |
| OpenClaw family matches | 0 | 70 | 70 |
| Exact version matches | 0 | 25 | 25 |
| Vulnerability correlations | 0 | 10 | 10 |

Key rates from the title-query pass:

- Active candidate-to-family-match rate: 70 / 100, or 70%.
- Active candidate-to-exact-version rate: 25 / 100, or 25%.
- Passive-to-family-match rate: 70 / 500, or 14%.

Deeper CSV review produced these additional findings:

- Passive gating held in field data: 65 passive candidates carried
  `product_confidence=1.0` and non-correlating version-like evidence, yet still
  produced 0 exact versions and 0 vulnerability correlations. Under the older
  passive-banner logic, these rows were the kind of data that could have become
  passive-only version or vulnerability false positives.
- The 25 exact-versioned active hosts were distributed across `2023.11.3` (8),
  `2026.5.28` (7), `2026.5.7` (4), and one host each on
  `2026.1.29-beta.1`, `2026.2.2-1`, `2026.5.3-1`, `2026.5.18`,
  `2026.5.22`, and `2026.5.27`.
- Vulnerability correlation stayed evidence-gated: 8 `2023.11.3` hosts
  correlated to 32 records each, one `2026.1.29-beta.1` host correlated to 30,
  and one `2026.2.2-1` host correlated to 29. No passive-only row produced a
  vulnerability correlation.
- Version suffix preservation was field-confirmed for `2026.2.2-1`,
  `2026.1.29-beta.1`, and `2026.5.3-1`.
- The 30 active rows without family matches split into false-positive,
  error-heavy, and responsive/no-family buckets. The responsive/no-family rows
  clustered around `200:35;400:2;404:1` or the `401` auth-challenge variant and
  are the next rule-mining target.
- The passive candidate set included obvious non-OpenClaw products such as
  Ivanti EPMM, Sophos SSL VPN, D-Link webcam, Ncat proxy, IIS, and Apache. The
  scanner now annotates or downgrades these passive candidates instead of
  treating discovery confidence as identification.

Deep validation did not change family, exact-version, or vulnerability counts
in this sample, but it added richer response-shape evidence. The most common
default status signatures were `200:19;404:19`, `200:17;404:19`, and
`101:2;200:17;404:19`; the most common deep-validation signatures were
`200:34;404:23;405:1`, `200:32;404:23;405:1`, and
`101:2;200:32;404:23;405:1`.

These signatures are tracked as correlation signals for future version,
deployment-mode, and reverse-proxy analysis, but they are not treated as
exact-version proof by themselves.

Public-safe anonymized artifacts live under:

- `artifacts/shodan/2026-06-02/public/`
- `artifacts/shodan/2026-06-03/public/`

## Public Exposure Checker

Live authorized self-assessment page:
<https://mahdihedhli.github.io/openclaw_scanner/checker/>

The repo includes a deployable GitHub Pages checker frontend under `site/` and
a Cloudflare Worker API under `cloudflare/worker/`. The page is intentionally
static and does not scan by itself; it calls the separate rate-limited Worker
backend for one authorized, low-impact check.

The checker flow is deliberately constrained:

- the user must confirm: "I confirm that I own this system or am explicitly
  authorized to assess it."
- the user must complete CAPTCHA before a request is accepted
- the backend validates targets and blocks localhost, private, link-local,
  multicast, metadata, reserved, and internal-hostname targets
- the checker path uses low-impact GET checks only
- no POST probes, authentication attempts, debugger socket connections, VNC
  interaction, or payload execution are allowed
- vulnerability output is suppressed unless correlation-grade exact version
  evidence exists
- deployment details live in `docs/exposure-checker.md`

## Documentation

- Canonical GitHub repo: <https://github.com/MahdiHedhli/openclaw_scanner>
- [Roadmap](docs/roadmap.md)
- [Known-version corpus workflow](docs/corpus-workflow.md)
- [Announcement draft](docs/openclaw-scanner-announcement.md)
- [June 2026 calibration blog update](docs/openclaw-scanner-blog-update-2026-06-03.md)
- [Static exposure checker](docs/checker/index.html)
- [Exposure checker API contract](docs/checker/api-contract.json)
- [Exposure checker deployment guide](docs/exposure-checker.md)

## Known-Version Corpus

The bundled exact-version rules currently include 17 lab-promoted OpenClaw
releases:

<details>
<summary>Show covered releases</summary>

- `2026.1.29-beta.1`
- `2026.2.2-1`
- `2026.2.6`
- `2026.2.13`
- `2026.2.21`
- `2026.5.3-1`
- `2026.5.7`
- `2026.5.18`
- `2026.5.19-beta.1`
- `2026.5.20`
- `2026.5.22`
- `2026.5.24-beta.1`
- `2026.5.24-beta.2`
- `2026.5.25-beta.1`
- `2026.5.26`
- `2026.5.27`
- `2026.5.28`

</details>

These rules are based on short-lived VLAN 30 captures and should be treated as
high-value triage evidence. They are not exploit proof, and unusual deployment
modes, proxies, custom builds, or hidden static assets can still reduce a scan
to family-level confidence. As of the 2026-06-02 release-watch run, the stable
package gap is closed through `2026.5.28`. As of a 2026-06-04 npm registry
check, the latest published OpenClaw package is `2026.6.1`; that release is not
yet lab-promoted in this scanner and should go through the bounded release-watch
capture workflow before exact-version rules are added.

## Input formats

### Direct targets

Pass one or more `--target` values or use `--targets-file`.

Examples:

- `https://host.example:18789`
- `http://10.0.0.5:8080`
- `gateway.example.com:18789`
- `192.0.2.10`

When a target does not include a scheme, the scanner defaults to trying
`https://` first and falls back to `http://`.

### Shodan export

The scanner accepts these common forms:

- a JSON object containing a `matches` array
- a top-level JSON array of result objects
- newline-delimited JSON where each line is a Shodan match object

Useful fields include `ip_str`, `port`, `hostnames`, and `ssl`.
If a Shodan record includes a favicon hash, the scanner imports that passive
signal into the offline observation model.
The scanner also imports Shodan product/version, OS, CPE, hash pivots,
`ssl.jarm`, Shodan-reported CVE IDs, and structured mDNS gateway metadata when
those fields are present.

By default, Shodan exports are analyzed offline from the JSON itself. Use
`--rescan-shodan` if you want to actively probe each exported host.

### Censys, FOFA, and CT exports

The scanner normalizes additional passive datasets into the same internal target
record used by Shodan imports:

- `--censys-file` accepts JSON, JSONL, or CSV exports with host/service rows.
- `--fofa-file` accepts JSON, JSONL, CSV, and FOFA `fields` + `results` JSON.
- `--ct-file` accepts passive certificate-transparency exports and imports only
  names containing `openclaw`, `clawbot`, `clawdbot`, or `moltbot`.

Normalized imports preserve safe passive signals such as HTTP title, HTTP
status, server header, favicon hash, TLS/JARM metadata, certificate CN/SAN
names, and discovery confidence/source labels. Credential-bearing headers such
as `Authorization`, `Cookie`, `Set-Cookie`, and API-key headers are dropped from
normalized external records before they can enter scanner artifacts.

Passive TLS, provider, and CT metadata can raise discovery confidence, but they
do not independently produce exact-version claims.

### Live Shodan search

Use one or more `--shodan-query` values to fetch banners directly from the
Shodan REST API. The scanner looks for the API key in this order:

- `--shodan-key`
- `SHODAN_API_KEY` in the current environment
- `SHODAN_API_KEY=...` in `.env`
- `.shodanapi` in the repo root or `openclaw_scanner/.shodanapi`
  Raw tokens and `key=...` / `SHODAN_API_KEY=...` formats are both supported.

Useful flags:

- `--list-discovery-queries` to list reusable Shodan discovery query IDs
- `--discovery-query shodan-title-openclaw-control` to run a built-in query ID
- `--shodan-pages 3` to paginate through multiple result pages
- `--shodan-fields ip_str,port,http.title,data` to request a narrower field set
- `--shodan-minify` to use Shodan's smaller response mode
- `--rescan-shodan` to actively probe the returned hosts after ingestion

The live query path can consume Shodan query credits, especially if you use
search filters or fetch pages beyond the first one.

### Active validation controls

`--probe-ports` is opt-in. When supplied without a value, discovery-derived
hosts are tried on `18789,8080,8443,9000,3000,5000` in addition to the imported
port. You can provide a custom comma-separated list, for example
`--probe-ports 18789,8443`.

`--deep-validation` adds a second phase only after the base probes already
produce a strong OpenClaw-family fingerprint. That phase collects additional
presence, status, headers, and response-shape evidence for Socket.IO polling,
noVNC, websockify, OpenAI-compatible GET routes, browser-tool routes,
canvas-related routes, CORS preflight behavior, and WebSocket upgrade behavior.
It does not authenticate, connect to debugger sockets, attach to VNC, send tool
execution payloads, or establish a browser debugger session.

POST probes are disabled by default. Add `--enable-post-probes` with
`--deep-validation` if you explicitly want empty-body or `{}` method-aware POST
checks on auth-gated API routes.

## Black-Box Calibration Workflow

The scanner stays focused on external discovery. The black-box workflow is only
for generating better remote fingerprint rules from controlled test nodes.

The intended loop is:

1. Stand up one or more known-version test gateways.
2. Scan them with `openclaw_scanner` and write a capture bundle using
   `--capture-output` plus `--capture-version`.
3. Repeat for other versions.
4. Run `--suggest-rules-from` across the saved bundles.
5. Review the generated candidate `version_rules` before promoting them into
   [`openclaw_scanner/data/openclaw_rules.json`](openclaw_scanner/data/openclaw_rules.json).

Important scope guardrails:

- Capture bundles store only remote-visible signals such as path/status pairs,
  method/status pairs, titles, content types, header order, stripped error
  text, favicon hashes, JSON keys, JS asset names, and body hashes.
- The version label is out-of-band metadata for calibration only.
- The scanner does not depend on host-side files, processes, or local config to
  fingerprint a remote target.
- Oracle Cloud free-tier deployment scripts for known-version calibration nodes
  live in [`deploy/oracle_free_tier/README.md`](deploy/oracle_free_tier/README.md).

## Custom fingerprint rules

The bundled vulnerability intelligence lives in:

- [`openclaw_scanner/data/openclaw_rules.json`](openclaw_scanner/data/openclaw_rules.json)

The rule file supports two layers:

- `fingerprint_rules` for family or behavior classification
- `version_rules` for exact or approximate version inference

Example family rule:

```json
{
  "id": "openclaw-ui-only-404-api",
  "family": "openclaw_ui_only_404_api",
  "label": "OpenClaw UI-only gateway with JSON /health and 404 API paths",
  "confidence": 0.93,
  "notes": "Observed on live port 18789 responders.",
  "all": [
    {
      "type": "title_contains",
      "path": "/",
      "value": "OpenClaw Control"
    },
    {
      "type": "path_status",
      "path": "/api/version",
      "statuses": [404]
    },
    {
      "type": "json_key",
      "path": "/health",
      "value": "ok"
    }
  ]
}
```

Example version rule:

```json
{
  "id": "lab-ui-family-2026-2",
  "version": "2026.2.x",
  "confidence": 0.78,
  "notes": "Example placeholder rule based on a known dashboard bundle.",
  "all": [
    {
      "type": "script_contains",
      "value": "dashboard.7f2f57d4.js"
    },
    {
      "type": "path_status",
      "path": "/api/version",
      "statuses": [404]
    }
  ]
}
```

Supported condition types:

- `path_status`
- `path_status_not`
- `method_status`
- `status_distribution_signature`
- `title_contains`
- `marker_present`
- `script_contains`
- `header_contains`
- `json_key`
- `body_hash`
- `body_contains`
- `error_pattern`
- `header_order`
- `has_stack_trace`
- `favicon_hash`
- `ws_upgrade_supported`
- `ws_upgrade_status`
- `ws_subprotocol_contains`
- `ws_extension_contains`
- `version_hint_prefix`
- `cdp_present`
- `cdp_debugger_url_present`
- `cdp_browser_family`
- `cdp_engine`

Useful passive metadata fields surfaced in results include:

- `mdns_version`
- `mdns_service_types`
- `mdns_instance_names`
- `mdns_txt_records`
- `mdns_advertised_ports`
- `mdns_product_markers`
- `proxy_detection`
- `honeypot_assessment`
- `status_distribution_signature`

The bundled family rules currently recognize:

- `claw_gateway_tools_invoke_auth_json`
- `chromium_devtools_exposed`
- `openclaw_cdp_devtools_exposed`
- `socketio_polling_handshake`
- `novnc_presence`
- `websockify_presence`
- `openclaw_openai_chat_surface_enabled`
- `openclaw_mdns_gateway_advertisement`
- `clawdbot_mdns_gateway_advertisement`
- `openclaw_ui_only_404_api`
- `openclaw_spa_fallback_all_200`
- `clawdbot_spa_fallback_all_200`
- `moltbot_spa_fallback_all_200`

| Family | UI title | `/api` | `/api/version` | `/health` | Interpretation |
| --- | --- | --- | --- | --- | --- |
| `openclaw_ui_only_404_api` | `OpenClaw Control` | `404 text/plain` | `404 text/plain` | `200 application/json` with `ok,status` | UI is present, but API paths return a stable `Not Found` body and `/health` is a real JSON liveness endpoint. |
| `openclaw_spa_fallback_all_200` | `OpenClaw Control` | `200 text/html` | `200 text/html` | `200 text/html` | API-looking routes fall back to the same SPA shell, so `200` here does not imply a real version endpoint. |
| `clawdbot_spa_fallback_all_200` | `Clawdbot Control` | `200 text/html` | `200 text/html` | `200 text/html` | Same SPA-fallback pattern as OpenClaw, but branded as Clawdbot. |
| `moltbot_spa_fallback_all_200` | `Moltbot Control` | `200 text/html` | `200 text/html` | `200 text/html` | Same SPA-fallback pattern as OpenClaw, but branded as Moltbot. |

Passive Shodan mDNS exports can also match gateway advertisement families:

| Family | Service | Required TXT markers | Interpretation |
| --- | --- | --- | --- |
| `openclaw_mdns_gateway_advertisement` | `_openclaw-gw._tcp.local` | `role=gateway`, `gatewayPort=18789` | Passive confirmation that an OpenClaw-family gateway advertises the default gateway port. |
| `clawdbot_mdns_gateway_advertisement` | `_clawdbot-gw._tcp.local` | `role=gateway`, `gatewayPort=18789` | Passive confirmation that a Clawdbot-family gateway advertises the default gateway port. |

These family and presence matches improve clustering and triage, but they do
not create vulnerability hits unless a correlation-grade version is also
inferred. Product-agnostic CDP, Socket.IO, noVNC, and websockify signals are
not standalone OpenClaw proof.

## Changelog-Derived Gateway Signals

Current official OpenClaw docs and release notes make the gateway HTTP surface
more useful for external fingerprinting than it was in early March 2026.

| Signal | Probe | Interpretation |
| --- | --- | --- |
| Auth-gated tools API | `POST /tools/invoke` returns `400/401/403/429` with JSON `error` | Strong Claw-family gateway signal. This endpoint is part of the current trusted-operator HTTP API surface, so a structured auth failure is more informative than a plain dashboard fetch. |
| OpenAI-compatible chat surface enabled | `POST /v1/chat/completions` returns `400/401/403/429` with JSON `error` | Treat as a feature-generation signal, not an exact version. It is consistent with newer OpenAI-compatible gateway behavior and indicates the chat route is active rather than absent or method-blocked. |
| Models path is real JSON | `GET /v1/models` or `GET /v1/models/openclaw/default` returns JSON | Potentially high-value when it happens, especially if the response contains `data`, `object`, or `id`. |
| Models path is only SPA fallback | `GET /v1/models` returns `200 text/html` with the control title | Do not treat this as a real models API. On current live targets this often mirrors the same dashboard shell as `/`. |

The scanner now treats these as gateway-surface signals rather than exact
version fingerprints. They are useful for product confirmation, behavior
clustering, and lower-bound feature dating, but not yet for exact vuln mapping
without an additional version hint.

## Suggested workflow

1. Run the scanner against targets or exported Shodan data.
2. Review the raw features plus any family matches in the JSON or CSV output.
3. Build artifact or behavior rules from your own lab captures.
4. Re-run the scanner with the enriched rule file.
5. Use the exact version or family match to prioritize vulnerability triage.

## Notes

- The vulnerability mapping is version-based. It does not prove exploitability.
- GHSA-only advisories discovered during the final research sweep are tracked in
  the research notes but are not bundled into default vuln matching until they
  are normalized into stable scanner data.
- The bundled vulnerability data now includes additional March 2026 advisories
  with fixes extending through `2026.3.2`, plus curated lower-risk additions
  from later research batches up to `2026.2.26`.
- A larger March 2026 research batch is still documented under
  [`research/proposed_changes/`](research/proposed_changes),
  but entries explicitly marked as needing verification are not bundled into
  default vuln matching yet.
- Platform-specific CVEs are filtered when banner OS data clearly mismatches and
  are marked more tentatively when the target platform is unknown.
- Some bundled CVEs require auth, specific tool permissions, or local access.
- Reverse proxies and custom dashboards can hide useful signals.
- Honeypot assessment is intentionally conservative and should be treated as a
  triage hint, not proof that a target is fake.
- Default live probing stays low-impact: the scanner uses GET requests and
  WebSocket upgrade-header checks only. A second validation phase is available
  with `--deep-validation` and only runs after a strong OpenClaw-family
  fingerprint. CORS OPTIONS checks and extra GET/WebSocket presence probes live
  in that conditional phase. Empty-body or `{}` JSON POST probes require
  explicit `--enable-post-probes`.
  WebSocket checks only send HTTP upgrade headers and record the visible
  handshake response; the scanner does not establish a full authenticated
  session.
- `--format csv` emits one summarized row per target for triage.
- CSV output includes top fingerprint-family columns in addition to versions and
  vulnerabilities, plus status distribution, passive Shodan product/platform/
  pivot columns, mDNS version, reverse-proxy columns, and honeypot assessment
  columns when available.
- `--format ndjson` emits one full JSON record per line for pipelines.
- JSON and NDJSON outputs include `fingerprint_matches` alongside
  `matched_versions`, `proxy_detection`, `honeypot_assessment`, and
  Shodan-derived metadata includes passive pivot queries, mDNS fields, and
  Shodan-vs-scanner CVE cross-reference data when applicable.
- Demo datasets are bundled under
  [`openclaw_scanner/data/`](openclaw_scanner/data).
- Large internet-scale use should respect rate limits and authorization.

## Future Scope

- Host-side scanning may be added later, but it is intentionally out of scope
  for the current external discovery tool.

## Tests

Run the local unit tests:

```bash
python3 -m unittest discover -s tests -v
```
