import rules from "../../../openclaw_scanner/data/openclaw_rules.json" with { type: "json" };

const AUTHORIZATION_ACK_TEXT = "I confirm that I own this system or am explicitly authorized to assess it.";
const DEFAULT_PROBE_PATHS = [
  "/",
  "/login",
  "/api/version",
  "/api/status",
  "/api/health",
  "/v1/models",
  "/ws",
  "/favicon.ico",
  "/manifest.json"
];
const PRODUCT_MARKERS = [
  "openclaw",
  "claw gateway",
  "openclaw-gw",
  "clawdbot-gw",
  "gateway token",
  "clawdbot",
  "moltbot"
];
const BLOCKED_SUFFIXES = [".local", ".localhost", ".internal", ".lan", ".home.arpa"];
const BLOCKED_IPV4_CIDRS = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4]
];
const METADATA_IPV4 = new Set(["169.254.169.254"]);

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};

export async function handleRequest(request, env, ctx = {}) {
  const origin = request.headers.get("Origin") || "";
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(env, origin) });
  }

  const url = new URL(request.url);
  if (request.method !== "POST" || url.pathname !== "/scan") {
    return jsonResponse({ error: "not found" }, 404, env, origin);
  }

  let payload;
  try {
    payload = await request.json();
  } catch {
    return jsonResponse({ error: "request body must be JSON" }, 400, env, origin);
  }

  let normalized;
  try {
    normalized = normalizeCheckerTarget(payload.target);
    validateAuthorization(payload);
  } catch (error) {
    return jsonResponse({ error: error.message }, 400, env, origin);
  }

  const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
  const captcha = await verifyTurnstile(payload.captcha_token, clientIp, env);
  if (!captcha.success) {
    return jsonResponse({ error: "CAPTCHA validation failed" }, 403, env, origin);
  }

  const ipLimit = await consumeRateLimit(
    env.CHECKER_RATE_LIMITS,
    `ip:${hashKey(clientIp)}`,
    numberEnv(env, "IP_RATE_LIMIT_PER_HOUR", 5),
    3600
  );
  if (!ipLimit.allowed) {
    return jsonResponse(
      { error: "source IP rate limit exceeded", reset_after_seconds: ipLimit.resetAfterSeconds },
      429,
      env,
      origin
    );
  }

  const targetLimit = await consumeRateLimit(
    env.CHECKER_RATE_LIMITS,
    `target:${hashKey(normalized.href)}`,
    numberEnv(env, "TARGET_RATE_LIMIT_PER_HOUR", 3),
    3600
  );
  if (!targetLimit.allowed) {
    return jsonResponse(
      { error: "target rate limit exceeded", reset_after_seconds: targetLimit.resetAfterSeconds },
      429,
      env,
      origin
    );
  }

  try {
    await validateResolvedTarget(normalized, env);
    const result = await runSafeScan(normalized, env);
    return jsonResponse(result, 200, env, origin);
  } catch (error) {
    const status = error.statusCode || 400;
    return jsonResponse({ error: error.message }, status, env, origin);
  }
}

export function validateAuthorization(payload) {
  if (payload?.authorization_acknowledged !== true) {
    throw new Error("authorization acknowledgement is required");
  }
  if (!String(payload?.captcha_token || "").trim()) {
    throw new Error("CAPTCHA token is required");
  }
  return true;
}

export function normalizeCheckerTarget(value) {
  if (!String(value || "").trim()) {
    throw new Error("target is required");
  }
  const raw = String(value).trim();
  let parsed;
  try {
    parsed = new URL(raw.includes("://") ? raw : `https://${raw}`);
  } catch {
    throw new Error("target is malformed");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("target scheme must be http or https");
  }
  if (parsed.username || parsed.password) {
    throw new Error("target must not include credentials");
  }
  if (!parsed.hostname) {
    throw new Error("target hostname is required");
  }
  validateHostname(parsed.hostname);
  parsed.hash = "";
  parsed.search = "";
  if (!parsed.pathname) {
    parsed.pathname = "/";
  }
  return parsed;
}

export function validateHostname(hostname) {
  const host = String(hostname || "").trim().replace(/^\[(.*)\]$/, "$1").replace(/\.$/, "").toLowerCase();
  if (!host || host === "localhost" || host === "localhost.localdomain") {
    throw new Error("localhost targets are blocked");
  }
  if (BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    throw new Error("internal hostname suffix is blocked");
  }
  if (!host.includes(".") && !host.includes(":")) {
    throw new Error("single-label internal hostnames are blocked");
  }
  if (isIPv4(host)) {
    validatePublicIPv4(host);
  }
  if (host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:")) {
    throw new Error("non-public IPv6 targets are blocked");
  }
}

export function validatePublicIPv4(ip) {
  if (METADATA_IPV4.has(ip)) {
    throw new Error("cloud metadata IP targets are blocked");
  }
  const value = ipv4ToInt(ip);
  for (const [base, prefix] of BLOCKED_IPV4_CIDRS) {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    if ((value & mask) === (ipv4ToInt(base) & mask)) {
      throw new Error("non-public IP targets are blocked");
    }
  }
}

export async function validateResolvedTarget(parsed, env) {
  if (isIPv4(parsed.hostname)) {
    validatePublicIPv4(parsed.hostname);
    return true;
  }
  const records = await resolvePublicDns(parsed.hostname, env);
  if (!records.length) {
    throw Object.assign(new Error("target DNS did not resolve to public A/AAAA records"), { statusCode: 400 });
  }
  for (const address of records) {
    if (isIPv4(address)) {
      validatePublicIPv4(address);
    } else {
      validateHostname(address);
    }
  }
  return true;
}

async function resolvePublicDns(hostname, env) {
  const timeoutMs = numberEnv(env, "CHECKER_TIMEOUT_MS", 4000);
  const names = [];
  const queries = [
    ["A", 1],
    ["AAAA", 28]
  ];
  for (const [type, answerType] of queries) {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`;
    const response = await fetchWithTimeout(url, {
      headers: { Accept: "application/dns-json" }
    }, timeoutMs);
    if (!response.ok) {
      continue;
    }
    const data = await response.json();
    for (const answer of data.Answer || []) {
      if (answer && answer.type === answerType && answer.data) {
        names.push(String(answer.data));
      }
    }
  }
  return [...new Set(names)];
}

export async function verifyTurnstile(token, clientIp, env) {
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    return { success: false };
  }
  const form = new FormData();
  form.append("secret", secret);
  form.append("response", String(token || ""));
  if (clientIp && clientIp !== "unknown") {
    form.append("remoteip", clientIp);
  }
  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: form
  });
  if (!response.ok) {
    return { success: false };
  }
  return response.json();
}

export async function consumeRateLimit(kv, key, limit, windowSeconds, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!kv) {
    return { allowed: false, remaining: 0, resetAfterSeconds: windowSeconds };
  }
  const raw = await kv.get(key);
  const cutoff = nowSeconds - windowSeconds;
  const events = raw
    ? JSON.parse(raw).filter((timestamp) => Number(timestamp) > cutoff)
    : [];
  const allowed = events.length < limit;
  if (allowed) {
    events.push(nowSeconds);
  }
  await kv.put(key, JSON.stringify(events), { expirationTtl: windowSeconds + 60 });
  const resetAt = events.length ? Math.min(...events) + windowSeconds : nowSeconds + windowSeconds;
  return {
    allowed,
    remaining: Math.max(limit - events.length, 0),
    resetAfterSeconds: Math.max(resetAt - nowSeconds, 0)
  };
}

export async function runSafeScan(parsed, env) {
  const observations = [];
  const maxRedirects = numberEnv(env, "CHECKER_MAX_REDIRECTS", 2);
  const maxBytes = numberEnv(env, "CHECKER_MAX_RESPONSE_BYTES", 32768);
  const timeoutMs = numberEnv(env, "CHECKER_TIMEOUT_MS", 4000);

  for (const path of DEFAULT_PROBE_PATHS) {
    const url = new URL(path, `${parsed.protocol}//${parsed.host}`);
    observations.push(await fetchObservation(url, { maxRedirects, maxBytes, timeoutMs }, env));
  }

  const familyMatches = rules.fingerprint_rules
    .filter((rule) => ruleMatches(rule, observations))
    .sort((a, b) => Number(b.confidence || 0) - Number(a.confidence || 0));
  const versionMatches = rules.version_rules
    .filter((rule) => ruleMatches(rule, observations))
    .sort((a, b) => Number(b.confidence || 0) - Number(a.confidence || 0));
  const exactVersion = versionMatches[0]?.version || null;
  const vulnerabilityCount = exactVersion ? correlateVulnerabilities(exactVersion, rules.vulnerabilities || []).length : 0;
  const reachable = observations.some((observation) => typeof observation.status === "number");
  const possibleOpenClaw = familyMatches.length > 0 || versionMatches.length > 0 || productConfidence(observations) > 0;

  return {
    reachable,
    possible_openclaw: possibleOpenClaw,
    family_match: familyMatches.length > 0,
    exact_version: exactVersion,
    risk_context: riskContext({ exactVersion, vulnerabilityCount, familyMatches, possibleOpenClaw, reachable }),
    evidence_summary: evidenceSummary({ observations, familyMatches, versionMatches, vulnerabilityCount })
  };
}

async function fetchObservation(url, options, env) {
  const headers = new Headers({
    "User-Agent": "openclaw-exposure-checker/0.1",
    Accept: "text/html,application/json,text/plain;q=0.8,*/*;q=0.2"
  });
  let current = new URL(url);
  let response = null;
  let redirects = 0;
  while (redirects <= options.maxRedirects) {
    response = await fetchWithTimeout(current.href, {
      method: "GET",
      headers,
      redirect: "manual"
    }, options.timeoutMs);
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      break;
    }
    const location = response.headers.get("Location");
    if (!location) {
      break;
    }
    current = new URL(location, current);
    normalizeCheckerTarget(current.href);
    await validateResolvedTarget(current, env);
    redirects += 1;
  }

  const text = response ? await readBoundedText(response, options.maxBytes) : "";
  const lower = text.toLowerCase();
  const contentType = response?.headers.get("content-type") || "";
  return {
    path: url.pathname,
    method: "GET",
    status: response?.status,
    contentType,
    title: extractTitle(text),
    scripts: extractScripts(text),
    bodySha256: await sha256Hex(text),
    jsonKeys: extractJsonKeys(text, contentType),
    markers: PRODUCT_MARKERS.filter((marker) => lower.includes(marker)),
    headerValues: stableHeaders(response?.headers),
    bodyLength: text.length
  };
}

async function fetchWithTimeout(url, init, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function readBoundedText(response, maxBytes) {
  if (!response.body) {
    return "";
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (total < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    const remaining = maxBytes - total;
    const chunk = value.slice(0, remaining);
    chunks.push(chunk);
    total += chunk.length;
    if (chunk.length < value.length) {
      await reader.cancel();
      break;
    }
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(concatBytes(chunks, total));
}

function ruleMatches(rule, observations) {
  const all = rule.all || [];
  const any = rule.any || [];
  if (all.length && !all.every((condition) => conditionMatches(condition, observations))) {
    return false;
  }
  if (any.length && !any.some((condition) => conditionMatches(condition, observations))) {
    return false;
  }
  return all.length > 0 || any.length > 0;
}

function conditionMatches(condition, observations) {
  const path = condition.path || "/";
  const observation = observations.find((item) => item.path === path);
  if (!observation) return false;
  const value = String(condition.value ?? "").toLowerCase();
  switch (condition.type) {
    case "path_status":
      return Number(observation.status) === Number(condition.value);
    case "method_status":
      if (condition.method && String(condition.method).toUpperCase() !== observation.method) {
        return false;
      }
      return Number(observation.status) === Number(condition.value);
    case "title_contains":
      return String(observation.title || "").toLowerCase().includes(value);
    case "script_contains":
      return observation.scripts.some((script) => script.toLowerCase().includes(value));
    case "body_hash":
      return observation.bodySha256 === String(condition.value);
    case "marker_present":
      return observation.markers.includes(String(condition.value).toLowerCase());
    case "json_key":
      return observation.jsonKeys.includes(String(condition.value));
    case "header_contains":
      return Object.values(observation.headerValues).some((headerValue) => String(headerValue).toLowerCase().includes(value));
    default:
      return false;
  }
}

function productConfidence(observations) {
  if (observations.some((observation) => observation.markers.length > 0)) return 0.7;
  if (observations.some((observation) => /openclaw|clawdbot|moltbot/i.test(observation.title || ""))) return 0.7;
  return 0;
}

function evidenceSummary({ observations, familyMatches, versionMatches, vulnerabilityCount }) {
  const summary = [];
  const statuses = statusDistribution(observations);
  if (Object.keys(statuses).length) {
    summary.push(`status_distribution_signature=${formatStatusDistribution(statuses)}`);
  }
  if (familyMatches[0]) {
    summary.push(`family=${familyMatches[0].label || familyMatches[0].family}`);
  }
  if (versionMatches[0]) {
    summary.push(`exact_version=${versionMatches[0].version}; source=${versionMatches[0].id}`);
  }
  if (vulnerabilityCount > 0) {
    summary.push(`vulnerability_correlation_count=${vulnerabilityCount}`);
  }
  const markers = [...new Set(observations.flatMap((observation) => observation.markers))];
  if (markers.length) {
    summary.push(`remote_markers=${markers.slice(0, 5).join(",")}`);
  }
  return summary.slice(0, 8);
}

function riskContext({ exactVersion, vulnerabilityCount, familyMatches, possibleOpenClaw, reachable }) {
  if (!reachable) return "target was not reachable by low-impact checks";
  if (exactVersion && vulnerabilityCount > 0) return "known version identified with bundled vulnerability correlation";
  if (exactVersion) return "known version identified";
  if (familyMatches.length) return "OpenClaw-family fingerprint found; exact version not established";
  if (possibleOpenClaw) return "possible OpenClaw exposure candidate; insufficient evidence for family match";
  return "no OpenClaw-specific evidence found";
}

function correlateVulnerabilities(version, vulnerabilities) {
  return vulnerabilities.filter((vulnerability) => (vulnerability.affected_ranges || []).some((range) => versionInRange(version, range)));
}

function versionInRange(version, range) {
  if (range.lt && compareVersions(version, range.lt) >= 0) return false;
  if (range.lte && compareVersions(version, range.lte) > 0) return false;
  if (range.gt && compareVersions(version, range.gt) <= 0) return false;
  if (range.gte && compareVersions(version, range.gte) < 0) return false;
  return true;
}

function compareVersions(a, b) {
  const left = parseVersion(a);
  const right = parseVersion(b);
  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    const l = left[i] ?? 0;
    const r = right[i] ?? 0;
    if (l !== r) return l > r ? 1 : -1;
  }
  return 0;
}

function parseVersion(value) {
  const match = String(value).match(/^(\d+)\.(\d+)\.(\d+)(?:-([a-z]+)\.?(\d+)?)?(?:-(\d+))?$/i);
  if (!match) return [0];
  const [, year, major, patch, label, labelNumber, build] = match;
  const prereleaseRank = label ? -1 : 0;
  return [Number(year), Number(major), Number(patch), prereleaseRank, Number(labelNumber || 0), Number(build || 0)];
}

function extractTitle(text) {
  const match = String(text || "").match(/<title[^>]*>(.*?)<\/title>/is);
  return match ? match[1].replace(/\s+/g, " ").trim() : "";
}

function extractScripts(text) {
  return [...String(text || "").matchAll(/<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']/gi)]
    .map((match) => match[1])
    .slice(0, 20);
}

function extractJsonKeys(text, contentType) {
  if (!String(contentType || "").toLowerCase().includes("json")) return [];
  try {
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return [];
    return Object.keys(parsed).slice(0, 40);
  } catch {
    return [];
  }
}

function stableHeaders(headers) {
  const result = {};
  if (!headers) return result;
  for (const name of ["server", "www-authenticate", "x-powered-by", "allow", "access-control-allow-origin", "access-control-allow-methods"]) {
    const value = headers.get(name);
    if (value) {
      result[name] = name === "www-authenticate" ? sanitizeAuthenticateHeader(value) : value;
    }
  }
  return result;
}

function sanitizeAuthenticateHeader(value) {
  const text = String(value || "");
  const scheme = text.match(/^\s*([A-Za-z][A-Za-z0-9_-]*)/)?.[1] || "";
  const realm = text.match(/\brealm\s*=\s*("?)([^",]+)\1/i)?.[2] || "";
  if (scheme && realm) return `${scheme} realm="${realm}"`;
  return scheme || "";
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(String(text || ""));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function statusDistribution(observations) {
  const counts = {};
  for (const observation of observations) {
    if (typeof observation.status !== "number") continue;
    counts[observation.status] = (counts[observation.status] || 0) + 1;
  }
  return counts;
}

function formatStatusDistribution(counts) {
  return Object.keys(counts).map(Number).sort((a, b) => a - b).map((status) => `${status}:${counts[status]}`).join(";");
}

function corsHeaders(env, origin) {
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map((item) => item.trim()).filter(Boolean);
  const allowOrigin = allowed.includes(origin) ? origin : allowed.includes("*") ? "*" : allowed[0] || "*";
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "600",
    Vary: "Origin"
  };
}

function jsonResponse(data, status, env, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...corsHeaders(env, origin)
    }
  });
}

function numberEnv(env, name, fallback) {
  const parsed = Number(env[name]);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function hashKey(value) {
  let hash = 2166136261;
  for (const char of String(value)) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

function isIPv4(value) {
  return /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(value);
}

function ipv4ToInt(ip) {
  return ip.split(".").reduce((acc, octet) => ((acc << 8) + Number(octet)) >>> 0, 0);
}

function concatBytes(chunks, total) {
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
