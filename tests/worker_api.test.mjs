import test from "node:test";
import assert from "node:assert/strict";
import {
  consumeRateLimit,
  handleRequest,
  metricsSummary,
  normalizeCheckerTarget,
  recordUsageMetric,
  sanitizeTelemetryPage,
  validateAuthorization,
  validateHostname,
  validatePublicIPv4,
  validateResolvedTarget
} from "../cloudflare/worker/src/index.js";

class MemoryKV {
  constructor() {
    this.map = new Map();
  }

  async get(key) {
    return this.map.get(key) || null;
  }

  async put(key, value) {
    this.map.set(key, value);
  }
}

test("normalizes host targets to https URLs", () => {
  const target = normalizeCheckerTarget("gateway.example.com:18789");
  assert.equal(target.href, "https://gateway.example.com:18789/");
});

test("rejects malformed or internal targets", () => {
  for (const target of [
    "ftp://gateway.example.com",
    "https://user:pass@gateway.example.com",
    "http://localhost:18789",
    "http://127.0.0.1:18789",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.1.10",
    "http://169.254.169.254",
    "http://service.internal",
    "http://gateway.local",
    "http://intranet"
  ]) {
    assert.throws(() => normalizeCheckerTarget(target), Error, target);
  }
});

test("public IP validator rejects blocked ranges", () => {
  for (const ip of ["127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.168.1.1"]) {
    assert.throws(() => validatePublicIPv4(ip), Error, ip);
  }
});

test("hostname validator blocks internal suffixes", () => {
  assert.throws(() => validateHostname("gateway.home.arpa"));
  assert.throws(() => validateHostname("singlelabel"));
});

test("authorization acknowledgement is required", () => {
  assert.throws(() => validateAuthorization({ authorization_acknowledged: false, captcha_token: "x" }));
  assert.throws(() => validateAuthorization({ authorization_acknowledged: true, captcha_token: "" }));
  assert.equal(validateAuthorization({ authorization_acknowledged: true, captcha_token: "x" }), true);
});

test("rate limiting is keyed and bounded", async () => {
  const kv = new MemoryKV();
  assert.equal((await consumeRateLimit(kv, "ip:a", 2, 3600, 100)).allowed, true);
  assert.equal((await consumeRateLimit(kv, "ip:a", 2, 3600, 101)).allowed, true);
  assert.equal((await consumeRateLimit(kv, "ip:a", 2, 3600, 102)).allowed, false);
  assert.equal((await consumeRateLimit(kv, "ip:b", 2, 3600, 103)).allowed, true);
});

test("DNS preflight only accepts concrete public A or AAAA answers", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    Answer: [
      { type: 5, data: "internal.example.local." }
    ]
  }), {
    status: 200,
    headers: { "content-type": "application/dns-json" }
  });

  try {
    await assert.rejects(
      () => validateResolvedTarget(normalizeCheckerTarget("gateway.example.com"), { CHECKER_TIMEOUT_MS: "1000" }),
      /target DNS did not resolve/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("telemetry page names are normalized to coarse buckets", () => {
  assert.equal(sanitizeTelemetryPage("/"), "home");
  assert.equal(sanitizeTelemetryPage("/openclaw_scanner/"), "home");
  assert.equal(sanitizeTelemetryPage("/checker/"), "checker");
  assert.equal(sanitizeTelemetryPage("/openclaw_scanner/checker/"), "checker");
  assert.equal(sanitizeTelemetryPage("/unexpected/path"), "other");
});

test("usage metrics record aggregate page views and daily unique visitors", async () => {
  const kv = new MemoryKV();
  const env = {
    CHECKER_RATE_LIMITS: kv,
    METRICS_RETENTION_DAYS: "30",
    METRICS_SALT: "test-salt"
  };
  const requestA = new Request("https://worker.example/telemetry", {
    headers: { "CF-Connecting-IP": "198.51.100.10" }
  });
  const requestB = new Request("https://worker.example/telemetry", {
    headers: { "CF-Connecting-IP": "198.51.100.11" }
  });

  await recordUsageMetric(env, requestA, "page_view", { page: "/checker/", unique: true, date: "2026-06-17" });
  await recordUsageMetric(env, requestA, "page_view", { page: "/checker/", unique: true, date: "2026-06-17" });
  await recordUsageMetric(env, requestB, "page_view", { page: "/", unique: true, date: "2026-06-17" });

  const summary = await metricsSummary(kv, 1, new Date("2026-06-17T12:00:00Z"));
  assert.equal(summary.totals.page_view, 3);
  assert.equal(summary.totals.page_view_unique, 2);
  assert.equal(summary.totals.pages.checker, 2);
  assert.equal(summary.totals.pages.home, 1);
});

test("telemetry endpoint records page views without target details", async () => {
  const kv = new MemoryKV();
  const env = {
    CHECKER_RATE_LIMITS: kv,
    ALLOWED_ORIGINS: "https://mahdihedhli.github.io",
    TELEMETRY_RATE_LIMIT_PER_HOUR: "120",
    METRICS_RETENTION_DAYS: "30",
    METRICS_SALT: "test-salt"
  };
  const response = await handleRequest(new Request("https://worker.example/telemetry", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: "https://mahdihedhli.github.io",
      "CF-Connecting-IP": "198.51.100.20"
    },
    body: JSON.stringify({ event: "page_view", page: "/checker/" })
  }), env);

  assert.equal(response.status, 202);
  const summary = await metricsSummary(kv, 1);
  assert.equal(summary.totals.page_view, 1);
  assert.equal(summary.totals.pages.checker, 1);
  assert.equal([...kv.map.keys()].some((key) => key.includes("gateway.example.com")), false);
});

test("metrics summary endpoint requires an admin bearer token", async () => {
  const kv = new MemoryKV();
  const env = {
    CHECKER_RATE_LIMITS: kv,
    ALLOWED_ORIGINS: "*",
    METRICS_ADMIN_TOKEN: "secret-token"
  };

  const rejected = await handleRequest(new Request("https://worker.example/metrics/summary?days=1"), env);
  assert.equal(rejected.status, 401);

  await recordUsageMetric(env, new Request("https://worker.example/scan", {
    headers: { "CF-Connecting-IP": "198.51.100.30" }
  }), "scan_completed", { date: new Date().toISOString().slice(0, 10) });

  const accepted = await handleRequest(new Request("https://worker.example/metrics/summary?days=1", {
    headers: { Authorization: "Bearer secret-token" }
  }), env);
  assert.equal(accepted.status, 200);
  const body = await accepted.json();
  assert.equal(body.totals.scan_completed, 1);
  assert.match(body.retention_note, /no raw IPs, targets/);
});
