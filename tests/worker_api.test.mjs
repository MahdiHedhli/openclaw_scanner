import test from "node:test";
import assert from "node:assert/strict";
import {
  consumeRateLimit,
  normalizeCheckerTarget,
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
