# OpenClaw Scanner Blog Update: June 2026 Calibration

This update uses anonymized calibration data only. Real IP addresses,
organizations, and instance names were replaced with stable synthetic IDs and
RFC5737 TEST-NET addresses so passive and active records can still be
correlated without identifying the original hosts.

## Summary

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

## Interpretation

Passive title discovery was useful for building a candidate list, but it did
not produce identification by itself. The passive-only pass produced zero
family matches, zero exact versions, and zero vulnerability correlations.

Active validation changed the picture. The default low-impact active pass found
70 OpenClaw family matches, 25 exact-version matches, and 10 vulnerability
correlations from correlation-grade evidence. The deep-validation pass produced
the same counts while collecting richer response-shape and status-distribution
evidence for future clustering.

This supports the scanner's core model:

- Discovery is candidate generation.
- Active service signal is live behavior.
- Family fingerprinting requires remote-visible OpenClaw evidence.
- Exact versions require lab-promoted rules or explicit correlation-grade
  metadata.
- Vulnerability correlation only follows correlation-grade version evidence.

## Status Distribution Signals

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
correlation-grade vulnerability matches. Enabling conditional deep validation
without POST probes did not change the counts, but it added richer
status-distribution evidence that should help future clustering and
fingerprint-corpus work.
