# OpenClaw Scanner

`openclaw_scanner` is a lightweight proof-of-concept for:

- ingesting direct targets or Shodan export data
- ingesting live Shodan search results through the Shodan REST API
- probing common OpenClaw gateway HTTP endpoints
- extracting stable fingerprint signals
- classifying live responder behavior families such as UI-only 404 API gateways
  or SPA-fallback API shells
- inferring OpenClaw versions when a version hint or custom rule matches
- mapping inferred versions to known OpenClaw vulnerabilities

The scanner avoids third-party Python dependencies so it can run with the stock
`python3` that is already available on most systems.

## What it does

For each target, the scanner:

1. probes a small set of HTTP endpoints such as `/`, `/login`, `/api`,
   `/api/version`, `/api/health`, and a deliberate 404-style API path
2. records headers, status codes, titles, JS asset paths, JSON key shapes,
   product markers, and version hints
3. applies family fingerprint rules plus version extraction rules from a JSON
   rule file
4. compares the resulting exact or approximate version candidates against a seeded OpenClaw
   vulnerability database

The bundled rules are intentionally conservative:

- behavior-family fingerprinting is supported out of the box for the live
  port `18789` families observed so far
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

By default, Shodan exports are analyzed offline from the JSON itself. Use
`--rescan-shodan` if you want to actively probe each exported host.

### Live Shodan search

Use one or more `--shodan-query` values to fetch banners directly from the
Shodan REST API. The scanner looks for the API key in this order:

- `--shodan-key`
- `SHODAN_API_KEY` in the current environment
- `SHODAN_API_KEY=...` in `.env`

Useful flags:

- `--shodan-pages 3` to paginate through multiple result pages
- `--shodan-fields ip_str,port,http.title,data` to request a narrower field set
- `--shodan-minify` to use Shodan's smaller response mode
- `--rescan-shodan` to actively probe the returned hosts after ingestion

The live query path can consume Shodan query credits, especially if you use
search filters or fetch pages beyond the first one.

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
- `title_contains`
- `marker_present`
- `script_contains`
- `header_contains`
- `json_key`
- `body_hash`
- `version_hint_prefix`

The bundled family rules currently recognize:

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

These family matches improve clustering and triage, but they do not create
vulnerability hits unless an exact or approximate version is also inferred.

## Suggested workflow

1. Run the scanner against targets or exported Shodan data.
2. Review the raw features plus any family matches in the JSON or CSV output.
3. Build artifact or behavior rules from your own lab captures.
4. Re-run the scanner with the enriched rule file.
5. Use the exact version or family match to prioritize vulnerability triage.

## Notes

- The vulnerability mapping is version-based. It does not prove exploitability.
- Some bundled CVEs require auth, specific tool permissions, or local access.
- Reverse proxies and custom dashboards can hide useful signals.
- `--format csv` emits one summarized row per target for triage.
- CSV output includes top fingerprint-family columns in addition to versions and
  vulnerabilities.
- `--format ndjson` emits one full JSON record per line for pipelines.
- JSON and NDJSON outputs include `fingerprint_matches` alongside
  `matched_versions`.
- Demo datasets are bundled under
  [`openclaw_scanner/data/`](/Users/mhedhli/Documents/Codex/OpenClawScanner/openclaw_scanner/data).
- Large internet-scale use should respect rate limits and authorization.

## Tests

Run the local unit tests:

```bash
python3 -m unittest discover -s tests -v
```
