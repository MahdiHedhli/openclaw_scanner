# OpenClaw Scanner

`openclaw_scanner` is a lightweight proof-of-concept for:

- ingesting direct targets or Shodan export data
- probing common OpenClaw gateway HTTP endpoints
- extracting stable fingerprint signals
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
3. applies generic version extraction plus optional custom rules from a JSON
   rule file
4. compares the resulting version candidates against a seeded OpenClaw
   vulnerability database

The bundled rules are intentionally conservative:

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

Actively re-probe each Shodan result instead of using the exported banner data:

```bash
python3 -m openclaw_scanner --shodan-file shodan-results.json --rescan-shodan
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

## Custom fingerprint rules

The bundled vulnerability intelligence lives in:

- [`openclaw_scanner/data/openclaw_rules.json`](/Users/mhedhli/Documents/Codex/OpenClawScanner/openclaw_scanner/data/openclaw_rules.json)

You can add custom version fingerprint rules under `version_rules`. Example:

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

## Suggested workflow

1. Run the scanner against targets or exported Shodan data.
2. Review the raw features in the JSON output.
3. Build artifact rules from your own lab captures.
4. Re-run the scanner with the enriched rule file.
5. Use the exact version or family match to prioritize vulnerability triage.

## Notes

- The vulnerability mapping is version-based. It does not prove exploitability.
- Some bundled CVEs require auth, specific tool permissions, or local access.
- Reverse proxies and custom dashboards can hide useful signals.
- Large internet-scale use should respect rate limits and authorization.

## Tests

Run the local unit tests:

```bash
python3 -m unittest discover -s tests -v
```
