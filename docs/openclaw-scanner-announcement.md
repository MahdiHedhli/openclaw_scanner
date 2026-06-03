# Announcing OpenClaw Scanner

OpenClaw Scanner is a lightweight, dependency-free triage tool for identifying
OpenClaw gateway exposure and collecting defensible fingerprint evidence from
passive internet datasets and live HTTP probes.

The goal is intentionally narrow: help defenders sort likely OpenClaw gateway
exposure from internet-scale noise without turning a scan result into an
unsupported vulnerability claim. Passive discovery is useful, but exact
versioning requires evidence that a live service actually exposes one of the
remote-visible fingerprints we have validated in the lab.

The tool is for authorized defensive assessment only. Active scanning of IPs or
services you are not authorized to assess is not supported.

## What It Does

OpenClaw Scanner can:

- ingest direct targets, target files, Shodan exports, or live Shodan API
  results
- list and run reusable Shodan discovery query IDs for OpenClaw, Clawdbot, and
  Moltbot control titles, mDNS advertisements, and lab-rule-derived favicon
  hashes
- normalize Shodan, Censys, FOFA, and passive CT exports into one internal
  target model
- parse passive mDNS, TLS, title, favicon, and certificate-name metadata for
  OpenClaw-family indicators
- actively probe common OpenClaw gateway, API, model, WebSocket, and static
  asset paths, with conditional deep validation available after a strong family
  signal
- keep default active probing to GET requests and WebSocket upgrade-header
  handshakes, with CORS OPTIONS, Socket.IO polling, noVNC, websockify,
  browser-tool, canvas, and extra OpenAI-compatible GET checks gated behind
  conditional deep validation
- collect headers, status codes, titles, JS asset paths, favicon hashes, JSON
  key shapes, body markers, version hints, and proxy/honeypot indicators
- infer conservative OpenClaw family matches and exact versions when a
  lab-promoted exact rule is supported by remote-visible evidence
- correlate inferred versions with the bundled OpenClaw vulnerability metadata

The scanner does not exploit hosts. It is designed for low-impact triage and
evidence collection. POST probes are disabled by default and require explicit
operator opt-in. It does not authenticate, send tool-execution payloads,
connect to browser debugger sockets, or interact with VNC.

## Initial Internet Exposure Check

For the first public-facing calibration pass, we looked at the first 500 Shodan
records advertising OpenClaw gateway mDNS metadata and then actively probed a
ranked shortlist of 100 candidates.

The sanitized result:

- 500 passive Shodan rows were processed.
- 100 candidates were selected for active validation.
- 14 of the 100 active candidates returned live HTTP signal.
- 13 of the 100 active candidates matched an OpenClaw family fingerprint.
- 0 of the 100 active candidates produced an exact version match.
- 0 vulnerability matches were reported from the active sample.

That gives us three useful funnel metrics:

- Candidate-to-responsive rate: 14 / 100, or 14%.
- Candidate-to-family-match rate: 13 / 100, or 13%.
- Passive-to-family-match rate: 13 / 500, or 2.6%.

The active sample also exposed a promising non-version fingerprint signal:
status distribution. Several responsive hosts clustered around signatures such
as `200:13;401:1;404:23` and `200:13;401:3;404:21`. The scanner now records
this as `status_distribution_signature`, a sorted count of non-null HTTP
statuses observed across the safe probe set. It is not treated as an exact
version claim by itself, but it is useful evidence for future clustering across
versions, deployment styles, and reverse proxy behavior.

That result is exactly why the scanner separates passive discovery from active
fingerprinting. mDNS advertisements are useful for finding candidates, but they
are not enough to claim a specific OpenClaw version. Exact version claims remain
reserved for static assets or other stable remote-visible signals observed on a
live service.

## Public-Safe Data

The working dataset has been anonymized before publication. Real IP addresses,
organizations, and service instance names were replaced with stable synthetic
values. The same `anon_id` and TEST-NET IP are reused across passive and active
files so readers can correlate passive discovery with active results without
identifying the original hosts.

Prepared artifacts:

- `artifacts/shodan/2026-06-02/public/openclaw-passive-500-anonymized.csv`
- `artifacts/shodan/2026-06-02/public/openclaw-active-100-anonymized.csv`
- `artifacts/shodan/2026-06-02/public/openclaw-active-responsive-14-anonymized.csv`
- `artifacts/shodan/2026-06-02/public/openclaw-passive-plus-active-500-anonymized.csv`

## Why Conservative Fingerprinting Matters

OpenClaw deployments can sit behind proxies, serve modified static bundles,
hide versioned assets, or expose only a subset of the expected API behavior.
Passive internet data can also lag reality. A scanner that overclaims exact
versions from stale metadata is more harmful than useful.

OpenClaw Scanner therefore treats results in layers:

- Candidate: passive mDNS, title, favicon, TLS, JARM, CT, or query metadata
  means "candidate worth checking."
- Active service signal: live low-impact HTTP/WebSocket behavior means "there
  is a responsive service with observable remote behavior."
- Family fingerprint: multiple remote-visible signals match likely OpenClaw
  gateway behavior.
- Exact version evidence: a lab-promoted rule or explicit correlation-grade
  metadata such as a package or `cliPath` version matched.
- Vulnerability correlation: a correlation-grade version intersects bundled
  vulnerability ranges.

This gives defenders a safer workflow: discover broadly, validate carefully,
and only escalate findings that have enough evidence behind them.

Passive metadata does not equal version evidence. CDP and Chromium DevTools
signals are browser-agent evidence, not standalone OpenClaw proof. Socket.IO,
noVNC, websockify, and CORS observations are presence or response-shape signals
unless later lab validation promotes a specific remote-visible rule.

## Current Coverage

The bundled exact-version corpus currently includes 17 lab-promoted OpenClaw
releases through `2026.5.28`. Those rules come from short-lived known-version
lab deployments and are validated against saved captures before promotion.

The field scan above did not produce exact version matches, which is still a
useful result: the scanner can distinguish exposed candidates from hosts where
we do not yet have enough active evidence to make a version claim.

## Getting Started

Scan a target:

```bash
python3 -m openclaw_scanner --target https://example-gateway:18789 --format pretty
```

Scan a target list:

```bash
python3 -m openclaw_scanner --targets-file targets.txt --format json --output results.json
```

Analyze a Shodan export passively:

```bash
python3 -m openclaw_scanner --shodan-file shodan-results.json --format csv --output triage.csv
```

List discovery queries:

```bash
python3 -m openclaw_scanner --list-discovery-queries
```

Import passive Censys, FOFA, or CT exports:

```bash
python3 -m openclaw_scanner --censys-file censys.json --fofa-file fofa.csv --ct-file ct.jsonl --format json
```

Actively validate Shodan-derived candidates:

```bash
python3 -m openclaw_scanner --shodan-file shodan-results.json --rescan-shodan --probe-ports --deep-validation --format json --output active-results.json
```

## What Comes Next

Next work is focused on improving the scanner without weakening the evidence
bar:

- continue twice-weekly release checks for new OpenClaw packages
- deploy one new version at a time in an isolated lab environment
- capture stable remote-visible signals
- promote only exact rules that survive saved-capture validation
- compare passive Shodan metadata against live HTTP behavior over more samples
- calibrate Censys/FOFA/CT discovery confidence against live behavior
- derive favicon and composite fingerprints only from validated saved captures
- keep public examples anonymized by default

OpenClaw Scanner is already useful as a triage tool. Its strongest value is not
that it always names a version; it is that it keeps the difference between
"candidate", "active OpenClaw-like service", and "exact known version" explicit.
