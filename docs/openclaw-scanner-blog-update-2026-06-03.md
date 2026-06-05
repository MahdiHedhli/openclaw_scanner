---
title: "OpenClaw Scanner: Fingerprint Exposed Gateways on Port 18789 (Open Source)"
description: "Open source OpenClaw scanner for fingerprinting exposed OpenClaw gateways, OpenClaw port 18789 scanner workflows, and evidence-first OpenClaw vulnerability triage."
keywords:
  - OpenClaw scanner
  - fingerprint exposed OpenClaw gateways
  - OpenClaw port 18789 scanner
  - OpenClaw vulnerability triage
  - openclaw gateway fingerprinting
  - shodan openclaw
---

# OpenClaw Scanner: Fingerprint Exposed Gateways on Port 18789 (Open Source)

OpenClaw Scanner is an open source OpenClaw scanner for defenders who need to
fingerprint exposed OpenClaw gateways, run OpenClaw port 18789 scanner
workflows, and perform evidence-first OpenClaw vulnerability triage without
turning passive discovery into unsupported vulnerability claims.

Canonical GitHub repo: <https://github.com/MahdiHedhli/openclaw_scanner>

This update uses anonymized calibration data only. Real IP addresses,
organizations, and instance names were replaced with stable synthetic IDs and
RFC5737 TEST-NET addresses so passive and active records can still be
correlated without identifying the original hosts.

## Summary: OpenClaw Port 18789 Scanner Calibration

The June 3 calibration pass tested the new discovery expansion work against
`http.title:"OpenClaw Control"`. We processed 500 passive candidates and
actively validated a 100-host shortlist twice:

- Pass A: default low-impact mode.
- Pass B: `--deep-validation` enabled, with POST probes disabled.

| Metric | Passive candidates | Active default | Active deep, no POST |
| --- | ---: | ---: | ---: |
| Results processed | 500 | 100 | 100 |
| Responsive active hosts | N/A | 100 | 100 |
| OpenClaw family matches | 0 | 70 | 70 |
| Exact version matches | 0 | 25 | 25 |
| Vulnerability correlations | 0 | 10 | 10 |

## Interpretation: Fingerprint Exposed OpenClaw Gateways

Passive title discovery was useful for building a candidate list, but it did
not produce identification by itself. The passive-only pass produced zero
family matches, zero exact versions, and zero vulnerability correlations.
That included 65 rows with `product_confidence=1.0`. The stricter evidence
model correctly kept those rows at candidate/visible-evidence level instead of
turning passive banner text into exact-version or vulnerability claims.

Active validation changed the picture. The default low-impact active pass found
70 OpenClaw family matches, 25 exact-version matches, and 10 vulnerability
correlations from correlation-grade evidence. The deep-validation pass produced
the same counts while collecting richer response-shape and status-distribution
evidence for future clustering.

The exact-version distribution is the important operational readout. Eight
hosts matched `2023.11.3`, and each correlated to 32 vulnerability records.
Two other legacy exact versions also correlated to vulnerability records:
`2026.1.29-beta.1` and `2026.2.2-1`. Current `2026.5.x` builds produced exact
matches without vulnerability correlations.

The field data also confirmed the version-evidence patch. Numeric and
prerelease suffixes survived in output for `2026.2.2-1`,
`2026.1.29-beta.1`, and `2026.5.3-1`, and passive banner text did not create
exact-version or vulnerability claims by itself.

This supports the scanner's core model:

- Discovery is candidate generation.
- Active service signal is live behavior.
- Family fingerprinting requires remote-visible OpenClaw evidence.
- Exact versions require lab-promoted rules or explicit correlation-grade
  metadata.
- Vulnerability correlation only follows correlation-grade version evidence.

## Status Distribution Signals for OpenClaw Gateway Fingerprinting

The active default pass showed several repeated response-distribution clusters:

| Signature | Hosts |
| --- | ---: |
| `200:19;404:19` | 30 |
| `200:17;404:19` | 20 |
| `101:2;200:17;404:19` | 15 |

With conditional deep validation enabled, the top clusters shifted:

| Signature | Hosts |
| --- | ---: |
| `200:34;404:23;405:1` | 20 |
| `200:32;404:23;405:1` | 16 |
| `101:2;200:32;404:23;405:1` | 14 |

These signatures are useful for clustering deployment modes, reverse proxies,
and future version-corpus candidates. They are not exact-version proof by
themselves.

The older `2023.11.3` cohort clustered around `200:35;400:2;404:1` and
`200:28;400:2;401:7;404:1`. The latter indicates auth-gated API behavior is
externally visible on at least one old exact-versioned host in the anonymized
sample.

The 30 active rows without family matches also split into useful buckets:
flat title/favicon false positives, error-heavy unreachable rows, and a smaller
responsive group with OpenClaw-like signal but no current family rule hit. The
responsive no-family group is the next rule-mining target.

## Passive Noise Notes for OpenClaw Vulnerability Triage

The passive candidate set still contains known non-OpenClaw products that
passed initial discovery filters, including Ivanti EPMM, Sophos SSL VPN, Ncat
proxy, D-Link webcam, IIS, and Apache. These should become negative or
secondary-filter signals so active validation budget is spent on better
candidates.

The scanner now implements this as passive-noise metadata. Obvious
non-OpenClaw products are downgraded or annotated in discovery output, but not
hard-suppressed from active validation when other OpenClaw-like evidence is
present.

## Exposure Checker Follow-Up

The public exposure checker should be deployed as a static GitHub Pages
frontend plus a separate rate-limited backend. GitHub Pages alone cannot bypass
browser CORS or perform reliable server-side scanning. The frontend requires an
authorization acknowledgement and CAPTCHA token, then calls a backend that
performs one low-impact GET-only check against one normalized public target.

The backend must block localhost, RFC1918, link-local, multicast, cloud
metadata, reserved, and internal-hostname targets, and it must not run POST
probes, authenticate, attach debugger sockets, interact with VNC, or execute
payloads. Vulnerability details should remain gated behind correlation-grade
exact version evidence.

## Public-Safe Artifacts

- `artifacts/shodan/2026-06-03/public/openclaw-passive-500-anonymized.csv`
- `artifacts/shodan/2026-06-03/public/openclaw-active-default-100-anonymized.csv`
- `artifacts/shodan/2026-06-03/public/openclaw-active-deep-100-anonymized.csv`
- `artifacts/shodan/2026-06-03/public/openclaw-calibration-comparison-summary.json`

## Draft Post Copy

OpenClaw Scanner's latest calibration pass reinforces the project's central
principle: discovery is not identification. A title-based Shodan query produced
500 plausible candidates, but passive metadata alone produced no family
matches, no exact versions, and no vulnerability correlations. After
low-impact active validation of a 100-host shortlist, the scanner identified 70
OpenClaw-family services, 25 exact known-version matches, and 10
correlation-grade vulnerability matches. The highest-priority finding was a
cohort of 8 exact `2023.11.3` gateways, each correlating to 32 vulnerability
records. Enabling conditional deep validation without POST probes did not
change the counts, but it added richer status-distribution evidence that
should help future clustering and fingerprint-corpus work.
