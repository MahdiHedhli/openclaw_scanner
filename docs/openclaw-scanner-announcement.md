---
title: "OpenClaw Scanner: Fingerprint Exposed Gateways on Port 18789 (Open Source)"
description: "Open source OpenClaw scanner for fingerprinting exposed OpenClaw gateways, OpenClaw port 18789 scanner workflows, and evidence-first OpenClaw vulnerability triage."
---

# OpenClaw Scanner: Fingerprint Exposed Gateways on Port 18789 (Open Source)

OpenClaw Scanner is a lightweight, dependency-free triage tool for identifying
OpenClaw gateway exposure and collecting defensible fingerprint evidence from
passive internet datasets and live HTTP probes.

Canonical GitHub repo: <https://github.com/MahdiHedhli/openclaw_scanner>

The goal is intentionally narrow: help defenders sort likely OpenClaw gateway
exposure from internet-scale noise without turning a scan result into an
unsupported vulnerability claim. Passive discovery is useful, but exact
versioning requires evidence that a live service actually exposes one of the
remote-visible fingerprints we have validated in the lab.

The tool is for authorized defensive assessment only. Active scanning of IPs or
services you are not authorized to assess is not supported.

## What It Does: OpenClaw Scanner for Gateway Fingerprinting

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

## Initial Internet Exposure Check: OpenClaw Port 18789 Scanner Results

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

## June 3 Follow-Up: Title Query Calibration

The next calibration pass used the expanded Shodan discovery query support for
`http.title:"OpenClaw Control"`. We normalized 500 passive candidates and
actively validated a 100-host shortlist in two modes:

- Pass A: default low-impact mode.
- Pass B: `--deep-validation` enabled, with POST probes still disabled.

Sanitized funnel results:

| Metric | Passive candidates | Active default | Active deep, no POST |
| --- | ---: | ---: | ---: |
| Results processed | 500 | 100 | 100 |
| Responsive active hosts | N/A | 100 | 100 |
| OpenClaw family matches | 0 | 70 | 70 |
| Exact version matches | 0 | 25 | 25 |
| Vulnerability correlations | 0 | 10 | 10 |

The main takeaway: title-based passive discovery produced a much stronger active
shortlist than the first mDNS-oriented sample, but passive metadata alone still
produced zero family matches, zero exact versions, and zero vulnerability
correlations. Discovery found candidates; active evidence produced
identification.

That passive result was not trivial. Sixty-five passive candidates reached
`product_confidence=1.0` because they carried strong candidate metadata, but the
new evidence model still produced zero exact versions and zero vulnerability
correlations for those rows. Under the older passive-banner logic, these are
the rows that could have become passive-only version or vulnerability false
positives.

The title-query pass also reinforced the value of status-distribution
fingerprinting. The most common default signatures were:

- `200:19;404:19`: 30 hosts.
- `200:17;404:19`: 20 hosts.
- `101:2;200:17;404:19`: 15 hosts.

With conditional deep validation enabled, the top signatures shifted as
additional low-impact GET/OPTIONS/WebSocket evidence was collected:

- `200:34;404:23;405:1`: 20 hosts.
- `200:32;404:23;405:1`: 16 hosts.
- `101:2;200:32;404:23;405:1`: 14 hosts.

Deep validation did not change family, exact-version, or vulnerability counts
for this sample. It did, however, enrich the observation set for future
clustering work.

The exact-versioned active cohort split into legacy and current builds. Eight
anonymized gateways matched `2023.11.3`, and each correlated to 32 bundled
vulnerability records. The field data also preserved full version suffixes for
`2026.2.2-1`, `2026.1.29-beta.1`, and `2026.5.3-1`; those values were not
collapsed to bare `YYYY.M.D` triples.

The next calibration lane is the high-signal/no-family bucket. Several
responsive rows carried signatures such as `200:35;400:2;404:1` or an
auth-challenge variant with `401` responses, but did not yet satisfy a current
OpenClaw family rule. Those rows should be mined against lab captures before any
new family or version rule is promoted.

The passive noise lane is equally important. The anonymized passive data
included likely non-OpenClaw products such as Ivanti EPMM, Sophos SSL VPN, IIS,
Apache default or generic banners, D-Link webcam, and Ncat proxy. The scanner
now treats those as downgrade or annotation signals for passive candidate
ranking, not as hard suppression of active validation.

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
- `artifacts/shodan/2026-06-03/public/openclaw-passive-500-anonymized.csv`
- `artifacts/shodan/2026-06-03/public/openclaw-active-default-100-anonymized.csv`
- `artifacts/shodan/2026-06-03/public/openclaw-active-deep-100-anonymized.csv`
- `artifacts/shodan/2026-06-03/public/openclaw-calibration-comparison-summary.json`

## Why Conservative OpenClaw Vulnerability Triage Matters

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

The first mDNS-oriented field scan did not produce exact version matches. The
June 3 title-query follow-up did produce 25 exact-version matches and 10
vulnerability correlations, all driven by correlation-grade evidence rather
than passive discovery confidence.

## Public Exposure Checker

A static GitHub Pages site cannot safely or reliably perform server-side
scanning by itself. The checker implementation therefore splits
responsibilities:

- GitHub Pages hosts the static landing page and checker UI from `site/`.
- Cloudflare Worker `openclaw-exposure-checker` accepts one authorized target at
  a time.
- Cloudflare KV namespace `CHECKER_RATE_LIMITS` stores source-IP and target
  rate-limit counters.
- The Worker requires the exact authorization acknowledgement and a Cloudflare
  Turnstile token before scanning.
- The backend validates and normalizes the target, blocks localhost, RFC1918,
  link-local, multicast, cloud metadata, reserved, internal-hostname targets,
  and DNS results without concrete public A/AAAA answers, then performs only
  low-impact GET checks.
- The backend returns high-level results only: reachable, possible candidate,
  family fingerprint found, exact version if correlation-grade evidence exists,
  and vulnerability correlation only when exact correlation-grade version
  evidence exists.

The checker does not support scanning IPs or services you are not authorized to
assess. It does not run POST probes, authenticate, connect to debugger sockets,
interact with VNC, or execute payloads.

Production launch still requires the real Turnstile widget and Worker secret;
test CAPTCHA keys are acceptable only for local or staging validation.

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

Export public-safe rule-mining candidates from an anonymized active result CSV:

```bash
python3 -m openclaw_scanner --calibration-candidates-from openclaw-active-default-100-anonymized.csv --format csv
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
