# OpenClaw Scanner

`openclaw_scanner` is a lightweight proof-of-concept for:

- ingesting direct targets or Shodan export data
- ingesting live Shodan search results through the Shodan REST API
- probing common OpenClaw gateway HTTP endpoints
- extracting stable fingerprint signals
- extracting passive Shodan banner metadata and pivot queries for offline hunting
- extracting passive mDNS service metadata from Shodan banners for gateway triage
- detecting likely reverse proxies and edge services from existing response data
- annotating likely honeypot or decoy behavior conservatively from strong signatures and timing uniformity
- classifying live responder behavior families such as UI-only 404 API gateways
  or SPA-fallback API shells
- inferring OpenClaw versions when a version hint or custom rule matches
- mapping inferred versions to known OpenClaw vulnerabilities with
  platform-aware correlation when banner OS data is available

The scanner avoids third-party Python dependencies so it can run with the stock
`python3` that is already available on most systems.

## What it does

For each target, the scanner:

1. probes a small set of HTTP endpoints such as `/`, `/login`, `/api`,
   `/api/version`, `/api/health`, `/api/skills`, `/api/agents`, `/metrics`,
   `/swagger.json`, `/robots.txt`, `/ws`, `/favicon.ico`, `/manifest.json`,
   `/asset-manifest.json`, `/v1/models`, `/v1/models/openclaw/default`,
   `POST /v1/embeddings`, `POST /v1/chat/completions`, `POST /v1/responses`,
   `POST /tools/invoke`, a deliberate method-aware 404-style API path, and
   WebSocket upgrade handshakes on `/ws` and `/socket.io/`
2. records headers, header ordering, status codes, stripped error text, stack
   trace hints, titles, favicon hashes, JS asset paths, JSON key shapes,
   product markers, single-sample response timing, and version hints
3. imports passive Shodan banner metadata such as product/version, hash pivots,
   OS hints, favicon hashes, Shodan-reported CVEs, and structured mDNS gateway
   metadata when that data exists
4. detects likely reverse proxies or WAF edges from collected headers and
   passive Shodan WAF hints
5. applies family fingerprint rules plus version extraction rules from a JSON
   rule file
6. compares the resulting exact or approximate version candidates against an
   expanded OpenClaw vulnerability database

The bundled rules are intentionally conservative:

- behavior-family fingerprinting is supported out of the box for the live
  port `18789` families observed so far
- gateway API surface fingerprinting is supported out of the box for
  auth-gated `POST /tools/invoke` and selective OpenAI-compatible `POST /v1/*`
  behavior on current live responders
- richer external error-response, favicon/manifest, and WebSocket-handshake
  signals are collected out of the box for future rule enrichment
- passive Shodan metadata extraction and pivot-query generation are supported
  out of the box
- passive mDNS metadata extraction is supported out of the box for Shodan
  exports and live Shodan API ingestion
- reverse-proxy detection is supported out of the box for both live probes and
  passive Shodan HTTP metadata
- conservative honeypot assessment is supported out of the box from strong
  response signatures plus timing-uniformity heuristics
- exact version extraction is supported out of the box
- vulnerability correlation is supported out of the box
- artifact-to-version fingerprinting is designed to be extended with your own
  lab data in `openclaw_scanner/data/openclaw_rules.json`

## Quick start

Scan a single target:

```bash
python3 -m openclaw_scanner --target https://127.0.0.1:18789 --format pretty
```

Scan a list of targets:

```bash
python3 -m openclaw_scanner --targets-file targets.txt --format json
```

Scan a Shodan export:

```bash
python3 -m openclaw_scanner --shodan-file shodan-results.json --format pretty
```

Write a CSV triage file:

```bash
python3 -m openclaw_scanner --shodan-file shodan-results.json --format csv --output triage.csv
```

Write full records as NDJSON:

```bash
python3 -m openclaw_scanner --shodan-file shodan-results.json --format ndjson --output triage.ndjson
```

Run a live Shodan query:

```bash
SHODAN_API_KEY=... python3 -m openclaw_scanner \
  --shodan-query 'product:"mDNS" "clawdbot-gw"' \
  --shodan-pages 2 \
  --format pretty
```

Actively re-probe each Shodan result instead of using the exported banner data:

```bash
python3 -m openclaw_scanner --shodan-file shodan-results.json --rescan-shodan
```

Use the bundled demo data:

```bash
python3 -m openclaw_scanner \
  --shodan-file openclaw_scanner/data/demo_18789-03-17-2026.json \
  --rescan-shodan \
  --format pretty
```

Write JSON output to a file:

```bash
python3 -m openclaw_scanner --targets-file targets.txt --output results.json
```

Project planning lives in [`docs/roadmap.md`](/Users/mhedhli/Documents/Codex/OpenClawScanner/docs/roadmap.md).
The Proxmox-backed known-version corpus workflow lives in
[`docs/corpus-workflow.md`](/Users/mhedhli/Documents/Codex/OpenClawScanner/docs/corpus-workflow.md).
That lifecycle requires a bounded known-version deployment command or an
explicit pre-deployed image override before scanner capture.

The bundled exact-version rules currently include 14 lab-promoted OpenClaw
releases:

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

These rules are based on short-lived VLAN 30 captures and should be treated as
high-value triage evidence. They are not exploit proof, and unusual deployment
modes, proxies, custom builds, or hidden static assets can still reduce a scan
to family-level confidence.

Create a black-box calibration capture bundle from known-version test nodes:

```bash
python3 -m openclaw_scanner \
  --targets-file lab-targets-2026.2.13.txt \
  --capture-version 2026.2.13 \
  --capture-name openclaw-2026.2.13-lab \
  --capture-output captures/openclaw-2026.2.13.json \
  --format pretty
```

Generate candidate version rules from saved black-box capture bundles:

```bash
python3 -m openclaw_scanner \
  --suggest-rules-from captures/ \
  --format json \
  --output candidate-version-rules.json
```

The suggestion report includes stable and unique signal counts plus lightweight
Jaccard similarity metrics. Use high intra-version similarity and low
nearest-other-version similarity as promotion criteria before adding a candidate
rule to the bundled rules file. The report also includes a conservative
`promotion` summary; treat `review_candidate` as a human-review queue, not an
automatic merge signal.

Provision disposable Oracle Cloud free-tier calibration nodes:

```bash
cp deploy/oracle_free_tier/terraform.tfvars.example deploy/oracle_free_tier/terraform.tfvars
cd deploy/oracle_free_tier
terraform init
terraform apply
```

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

### Live Shodan search

Use one or more `--shodan-query` values to fetch banners directly from the
Shodan REST API. The scanner looks for the API key in this order:

- `--shodan-key`
- `SHODAN_API_KEY` in the current environment
- `SHODAN_API_KEY=...` in `.env`
- `.shodanapi` in the repo root or `openclaw_scanner/.shodanapi`
  Raw tokens and `key=...` / `SHODAN_API_KEY=...` formats are both supported.

Useful flags:

- `--shodan-pages 3` to paginate through multiple result pages
- `--shodan-fields ip_str,port,http.title,data` to request a narrower field set
- `--shodan-minify` to use Shodan's smaller response mode
- `--rescan-shodan` to actively probe the returned hosts after ingestion

The live query path can consume Shodan query credits, especially if you use
search filters or fetch pages beyond the first one.

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
   [`openclaw_scanner/data/openclaw_rules.json`](/Users/mhedhli/Documents/Codex/OpenClawScanner/openclaw_scanner/data/openclaw_rules.json).

Important scope guardrails:

- Capture bundles store only remote-visible signals such as path/status pairs,
  method/status pairs, titles, content types, header order, stripped error
  text, favicon hashes, JSON keys, JS asset names, and body hashes.
- The version label is out-of-band metadata for calibration only.
- The scanner does not depend on host-side files, processes, or local config to
  fingerprint a remote target.
- Oracle Cloud free-tier deployment scripts for known-version calibration nodes
  live in [`deploy/oracle_free_tier/README.md`](/Users/mhedhli/Documents/Codex/OpenClawScanner/deploy/oracle_free_tier/README.md).

## Custom fingerprint rules

The bundled vulnerability intelligence lives in:

- [`openclaw_scanner/data/openclaw_rules.json`](/Users/mhedhli/Documents/Codex/OpenClawScanner/openclaw_scanner/data/openclaw_rules.json)

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

Useful passive metadata fields surfaced in results include:

- `mdns_version`
- `mdns_service_types`
- `mdns_instance_names`
- `mdns_txt_records`
- `mdns_advertised_ports`
- `mdns_product_markers`
- `proxy_detection`
- `honeypot_assessment`

The bundled family rules currently recognize:

- `claw_gateway_tools_invoke_auth_json`
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

These family matches improve clustering and triage, but they do not create
vulnerability hits unless an exact or approximate version is also inferred.

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
  [`research/proposed_changes/`](/Users/mhedhli/Documents/Codex/OpenClawScanner/research/proposed_changes),
  but entries explicitly marked as needing verification are not bundled into
  default vuln matching yet.
- Platform-specific CVEs are filtered when banner OS data clearly mismatches and
  are marked more tentatively when the target platform is unknown.
- Some bundled CVEs require auth, specific tool permissions, or local access.
- Reverse proxies and custom dashboards can hide useful signals.
- Honeypot assessment is intentionally conservative and should be treated as a
  triage hint, not proof that a target is fake.
- Default live probing stays low-impact: the scanner uses GET requests plus a
  small set of empty-body or `{}` JSON POST probes for method-aware error
  fingerprinting, including `POST /api/doesnotexist`, `POST /tools/invoke`,
  and the OpenAI-compatible `POST /v1/*` paths, along with a broader discovery
  path set for API, metrics, schema, config, and WebSocket-adjacent surfaces.
  WebSocket checks only send HTTP upgrade headers and record the visible
  handshake response; the scanner does not establish a full authenticated
  session.
- `--format csv` emits one summarized row per target for triage.
- CSV output includes top fingerprint-family columns in addition to versions and
  vulnerabilities, plus passive Shodan product/platform/pivot columns, mDNS
  version, reverse-proxy columns, and honeypot assessment columns when
  available.
- `--format ndjson` emits one full JSON record per line for pipelines.
- JSON and NDJSON outputs include `fingerprint_matches` alongside
  `matched_versions`, `proxy_detection`, `honeypot_assessment`, and
  Shodan-derived metadata includes passive pivot queries, mDNS fields, and
  Shodan-vs-scanner CVE cross-reference data when applicable.
- Demo datasets are bundled under
  [`openclaw_scanner/data/`](/Users/mhedhli/Documents/Codex/OpenClawScanner/openclaw_scanner/data).
- Large internet-scale use should respect rate limits and authorization.

## Future Scope

- Host-side scanning may be added later, but it is intentionally out of scope
  for the current external discovery tool.
- A future GitHub Pages exposure checker may let users enter their own public IP
  for testing, with rate limiting, a CAPTCHA, and an authorization warning
  before scanning.

## Tests

Run the local unit tests:

```bash
python3 -m unittest discover -s tests -v
```
