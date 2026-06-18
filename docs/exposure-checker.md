# OpenClaw Exposure Checker

The OpenClaw Exposure Checker is an authorized self-assessment path for users
who want to check one system they own or are explicitly authorized to assess.
It is not an internet-wide scanner and it is not a public vulnerability
scanner.

## Architecture

```text
GitHub Pages static UI
  -> Cloudflare Worker API
  -> Safe OpenClaw checker mode
```

The static site lives in `site/` and is deployable by GitHub Pages. It cannot
perform reliable server-side checks by itself, so it calls a separate
Cloudflare Worker API.

## Created Cloudflare Resources

- Worker script name: `openclaw-exposure-checker`
- Worker route: `https://openclaw-exposure-checker.mhedhli.workers.dev`
- KV namespace: `CHECKER_RATE_LIMITS`
- KV namespace id: `ea6a637801f34ac7b9e934947e0eb450`
- Turnstile widget name: `OpenClaw Exposure Checker`
- Turnstile hostname: `mahdihedhli.github.io`
- Turnstile wiring status: production public site key copied into
  `site/checker/config.js`; secret key set as the Worker
  `TURNSTILE_SECRET_KEY` secret.

## Authorization Model

The frontend disables the scan button until the user provides:

- a syntactically valid hostname or URL
- a completed CAPTCHA token
- this explicit acknowledgement:

```text
I confirm that I own this system or am explicitly authorized to assess it.
```

The Worker independently rejects requests without the acknowledgement or a
Turnstile token. Frontend checks are usability controls only; enforcement lives
in the Worker.

## Rate Limits

The Worker uses Cloudflare KV to enforce:

- 5 scans per hour per source IP
- 3 scans per hour per normalized target

Rate-limit keys are hashed before storage. KV entries expire shortly after the
one-hour window.

## CAPTCHA Design

Cloudflare Turnstile is the intended production CAPTCHA service.

- The static page reads `turnstileSiteKey` from `site/checker/config.js`.
- The Worker reads `TURNSTILE_SECRET_KEY` from a Worker secret.
- The Worker calls Turnstile Siteverify before any target validation, rate
  limit consumption, or scan execution.
- Test keys may be used only for local/staging validation; they are not a
  production deployment.

## SSRF Protections

The Worker accepts only `http` and `https` targets and blocks:

- localhost and loopback targets
- RFC1918/private IPv4 ranges
- carrier-grade NAT, link-local, multicast, reserved, and metadata IPv4 ranges
- localhost, `.local`, `.localhost`, `.internal`, `.lan`, and `.home.arpa`
  hostnames
- single-label internal hostnames
- local, unique-local, and link-local IPv6 prefixes

Before scanning a hostname, the Worker resolves public DNS through
Cloudflare DNS-over-HTTPS and accepts only concrete A or AAAA answers. CNAME
answers alone do not satisfy the preflight. Redirect targets are re-normalized
and re-validated before the Worker follows them.

## Scan Restrictions

Allowed:

- low-impact GET requests
- high-level status, title, hash, marker, and JSON-key observations

Forbidden:

- POST probes
- authentication attempts
- debugger socket connections
- VNC interaction
- payload execution
- raw response-body exposure in results

The current Worker performs GET-only checker probes. WebSocket upgrade checks
remain allowed by policy but are not required for the first deployment.

## Time Limits

The Worker enforces:

- request timeout: 4 seconds per fetch
- redirect limit: 2 redirects
- response body read cap: 32 KiB per observation

These limits keep checks bounded and reduce accidental load on user systems.

## Result Model

The API returns only high-level evidence:

```json
{
  "reachable": true,
  "possible_openclaw": true,
  "family_match": true,
  "exact_version": "2026.5.28",
  "risk_context": "known version identified",
  "evidence_summary": [
    "status_distribution_signature=200:5;401:1",
    "exact_version=2026.5.28; source=lab_rule_id"
  ]
}
```

Exact versions are returned only when the bundled evidence rules support an
exact-version match. Vulnerability context is summarized only after
correlation-grade exact-version evidence exists.

## Privacy Model

The public result view does not expose:

- raw scanner output
- response bodies
- credential-bearing headers
- debugger URLs
- internal diagnostics

The Worker records only aggregate operational telemetry needed to understand
whether the checker is useful:

- page views
- approximate daily unique page visitors
- scan requests
- CAPTCHA-passed scan submissions
- completed scans
- family-match, exact-version, and vulnerability-context result counts
- blocked validation, CAPTCHA, rate-limit, and error counts

The metrics layer does not store raw IPs, targets, hostnames, response bodies,
user agents, debugger URLs, credential-bearing headers, or raw scanner output.
Daily unique counts are approximate: the Worker stores only daily hashed visitor
markers and aggregate counters in KV. Counters are intended for directional
usage tracking, not billing-grade analytics.

## Usage Metrics

The static site sends a first-party `page_view` event to the Worker endpoint:

```text
POST /telemetry
```

The scan API records aggregate counters as the request moves through the safe
checker flow. A private summary endpoint returns recent daily rollups:

```bash
curl -H "Authorization: Bearer $METRICS_ADMIN_TOKEN" \
  "https://openclaw-exposure-checker.mhedhli.workers.dev/metrics/summary?days=30"
```

Required secret:

```bash
npx wrangler secret put METRICS_ADMIN_TOKEN --config cloudflare/worker/wrangler.toml
```

Recommended optional secret:

```bash
npx wrangler secret put METRICS_SALT --config cloudflare/worker/wrangler.toml
```

If `METRICS_SALT` is absent, the Worker still hashes unique markers with a
non-secret default namespace. Setting a secret salt improves privacy if KV
contents are ever exported for troubleshooting.

## Deployment Steps

1. Create a Cloudflare Turnstile widget for the GitHub Pages origin.
2. Set the Worker secret:

   ```bash
   npx wrangler secret put TURNSTILE_SECRET_KEY --config cloudflare/worker/wrangler.toml
   ```

3. Set the private metrics admin token:

   ```bash
   npx wrangler secret put METRICS_ADMIN_TOKEN --config cloudflare/worker/wrangler.toml
   ```

4. Optionally set a secret metrics salt:

   ```bash
   npx wrangler secret put METRICS_SALT --config cloudflare/worker/wrangler.toml
   ```

5. Update `site/checker/config.js` with the production Worker URL and
   Turnstile site key.
6. Update `ALLOWED_ORIGINS` in `cloudflare/worker/wrangler.toml` to the final
   GitHub Pages origin.
7. Deploy the Worker:

   ```bash
   npx wrangler deploy --config cloudflare/worker/wrangler.toml
   ```

8. Push `site/` and `.github/workflows/pages.yml` to `main` to trigger GitHub
   Pages deployment.
9. Validate authorization enforcement, CAPTCHA enforcement, rate limiting, SSRF
   blocking, and one authorized low-impact check against a system you control.

## Validation Checklist

- GitHub Pages publishes `site/`.
- Worker deploy succeeds.
- CAPTCHA is required before scan execution.
- Authorization checkbox keeps the button disabled until checked.
- API rejects missing acknowledgement.
- API rejects missing or invalid CAPTCHA.
- API rejects localhost, RFC1918, link-local, metadata, and internal hostname
  targets.
- API rate limits source IPs and normalized targets.
- API returns only the high-level result model.
- No POST probes are used by checker mode.
- Static Pages emits a `page_view` telemetry event.
- API increments scan outcome counters without storing raw targets.
- Metrics summary requires `METRICS_ADMIN_TOKEN`.

## 2026-06-05 Deployment Validation

- Cloudflare Worker deployed successfully at
  `https://openclaw-exposure-checker.mhedhli.workers.dev`.
- Worker version deployed: `8a7a885c-a96d-414c-891b-9a3e13ae0453`.
- GitHub Pages workflow deployment completed successfully for commit
  `cb38ab03bd8c7eb9e1ce76dbb72cff26ed1b1486`.
- GitHub Pages URL returned HTTP 200:
  `https://mahdihedhli.github.io/openclaw_scanner/`.
- Checker URL returned HTTP 200:
  `https://mahdihedhli.github.io/openclaw_scanner/checker/`.
- Published checker page contains the required authorization warning,
  authorization acknowledgement text, and disabled submit button.
- Worker CORS preflight returned HTTP 204 for the GitHub Pages origin.
- Worker rejected an invalid CAPTCHA token with HTTP 403 before scan execution.
- Worker rejected a loopback target with HTTP 400 and
  `non-public IP targets are blocked`.
- Production CAPTCHA wiring is complete: the frontend has the public site key
  and the Worker has the `TURNSTILE_SECRET_KEY` secret.
- Browser end-to-end validation completed against the project-owned GitHub Pages
  URL. Turnstile completed non-interactively, the authorized check submitted,
  and the result returned only high-level fields: reachable target, no
  OpenClaw-family match, no exact version, no vulnerability context, and a
  status-distribution evidence summary.
