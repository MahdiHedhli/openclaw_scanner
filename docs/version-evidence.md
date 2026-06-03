# Version Evidence Model

OpenClaw Scanner separates discovery, identification, and vulnerability
correlation. A version-like token may be useful evidence without being strong
enough to assert an exact version or map CVEs.

## Shared Grammar

All OpenClaw-family version extraction uses `openclaw_scanner/versions.py`.
The shared grammar preserves numeric build suffixes such as `2026.2.2-1` and
`2026.2.2-3`, plus prerelease counters such as `2026.5.19-beta.1`.

## Correlation Grade

Every `VersionMatch` has two evidence flags:

- `exact`: the evidence identifies a specific version rather than a broad
  window or visible candidate.
- `correlate`: the evidence is allowed to drive vulnerability matching.

`correlate_vulnerabilities()` ignores matches with `correlate=False`.

Correlation-grade evidence includes live marker-anchored version hints, explicit
mDNS package or `cliPath` metadata, and lab-promoted exact version rules.

Non-correlation-grade evidence includes discovery confidence, passive Shodan
banner text, generic mDNS TXT version tokens, approximate CDP/Chromium version
windows, and conditional deep-validation presence signals such as Socket.IO,
noVNC, websockify, CORS behavior, and browser-tool route shape. These signals
remain visible for triage and clustering where applicable, but they do not
produce vulnerability claims on their own.
