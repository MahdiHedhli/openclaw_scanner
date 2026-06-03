import hashlib
import json
import re
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from .models import ProbeObservation
from .versions import find_versions, find_versions_near_markers, version_sort_key


@dataclass
class ProbeConfig:
    path: str
    method: str = "GET"
    probe_name: Optional[str] = None
    websocket_upgrade: bool = False
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None


CORS_PREFLIGHT_HEADERS = {
    "Origin": "https://scanner.invalid",
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "authorization,content-type",
}

BASE_PROBE_CONFIGS = [
    ProbeConfig(path="/"),
    ProbeConfig(path="/login"),
    ProbeConfig(path="/api"),
    ProbeConfig(path="/api/version"),
    ProbeConfig(path="/api/status"),
    ProbeConfig(path="/api/health"),
    ProbeConfig(path="/api/skills"),
    ProbeConfig(path="/api/agents"),
    ProbeConfig(path="/api/devices"),
    ProbeConfig(path="/api/config"),
    ProbeConfig(path="/api/system/info"),
    ProbeConfig(path="/api/graphql"),
    ProbeConfig(path="/api/docs"),
    ProbeConfig(path="/health"),
    ProbeConfig(path="/status"),
    ProbeConfig(path="/v1/models"),
    ProbeConfig(path="/v1/models/openclaw/default"),
    ProbeConfig(path="/metrics"),
    ProbeConfig(path="/swagger.json"),
    ProbeConfig(path="/env.js"),
    ProbeConfig(path="/config.js"),
    ProbeConfig(path="/robots.txt"),
    ProbeConfig(path="/.well-known/security.txt"),
    ProbeConfig(path="/.well-known/openid-configuration"),
    ProbeConfig(path="/json/version", probe_name="cdp-version"),
    ProbeConfig(path="/json/list", probe_name="cdp-target-list"),
    ProbeConfig(path="/json", probe_name="cdp-target-list"),
    ProbeConfig(path="/devtools/browser", probe_name="cdp-browser"),
    ProbeConfig(path="/debug/pprof"),
    ProbeConfig(path="/debug/pprof/"),
    ProbeConfig(path="/ws"),
    ProbeConfig(path="/socket.io/"),
    ProbeConfig(path="/ws", probe_name="ws-upgrade", websocket_upgrade=True),
    ProbeConfig(path="/socket.io/", probe_name="ws-upgrade", websocket_upgrade=True),
    ProbeConfig(path="/api/doesnotexist"),
    ProbeConfig(path="/favicon.ico"),
    ProbeConfig(path="/manifest.json"),
    ProbeConfig(path="/asset-manifest.json"),
]

CONDITIONAL_DEEP_PROBE_CONFIGS = [
    ProbeConfig(
        path="/",
        method="OPTIONS",
        probe_name="cors-preflight",
        headers=CORS_PREFLIGHT_HEADERS,
    ),
    ProbeConfig(
        path="/tools/invoke",
        method="OPTIONS",
        probe_name="cors-preflight",
        headers=CORS_PREFLIGHT_HEADERS,
    ),
    ProbeConfig(path="/socket.io/?EIO=4&transport=polling&t=scanner"),
    ProbeConfig(path="/vnc.html"),
    ProbeConfig(path="/websockify"),
    ProbeConfig(path="/v1/completions"),
    ProbeConfig(path="/v1/chat/completions"),
    ProbeConfig(path="/v1/models"),
    ProbeConfig(path="/v1/responses"),
    ProbeConfig(path="/v1/embeddings"),
    ProbeConfig(path="/browser"),
    ProbeConfig(path="/browser-tool"),
    ProbeConfig(path="/browser-tools"),
    ProbeConfig(path="/api/browser"),
    ProbeConfig(path="/api/browser-tools"),
    ProbeConfig(path="/tools"),
    ProbeConfig(path="/tools/browser"),
    ProbeConfig(path="/tools/canvas"),
    ProbeConfig(path="/canvas"),
    ProbeConfig(path="/api/canvas"),
    ProbeConfig(path="/v1/canvas"),
    ProbeConfig(path="/ws", probe_name="ws-upgrade", websocket_upgrade=True),
]

POST_PROBE_CONFIGS = [
    ProbeConfig(path="/api/doesnotexist", method="POST", body=b""),
    ProbeConfig(
        path="/v1/embeddings",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=b"{}",
    ),
    ProbeConfig(
        path="/v1/chat/completions",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=b"{}",
    ),
    ProbeConfig(
        path="/v1/responses",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=b"{}",
    ),
    ProbeConfig(
        path="/tools/invoke",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=b"{}",
    ),
]

DEFAULT_PROBE_CONFIGS = list(BASE_PROBE_CONFIGS)

DEFAULT_PROBE_PATHS = list(
    dict.fromkeys(config.path for config in DEFAULT_PROBE_CONFIGS if config.method == "GET")
)

PRODUCT_MARKERS = [
    "openclaw",
    "claw gateway",
    "openclaw-gw",
    "_openclaw-gw._tcp.local",
    "clawdbot-gw",
    "_clawdbot-gw._tcp.local",
    "gateway token",
    "clawdbot",
    "moltbot",
]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SCRIPT_RE = re.compile(
    r"<script[^>]+src=[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']",
    re.IGNORECASE,
)
HTML_TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")

STACK_TRACE_PATTERNS = [
    re.compile(r"at\s+\S+\s+\([^)]+:\d+:\d+\)"),
    re.compile(r'Traceback \(most recent call last\)'),
    re.compile(r'File\s+"[^"]+",\s+line\s+\d+'),
    re.compile(r"goroutine\s+\d+\s+\[running\]"),
    re.compile(r"\S+\.go:\d+"),
    re.compile(r"thread\s+'[^']+'\s+panicked\s+at"),
    re.compile(r"Caused by:\s+[\w.]+Exception"),
]


def build_probe_configs(
    extra_paths: Optional[Iterable[str]] = None,
    include_post: bool = False,
    deep_validation: bool = False,
) -> List[ProbeConfig]:
    configs = list(BASE_PROBE_CONFIGS)
    if deep_validation:
        configs.extend(CONDITIONAL_DEEP_PROBE_CONFIGS)
    if include_post:
        configs.extend(POST_PROBE_CONFIGS)
    for path in extra_paths or []:
        configs.append(ProbeConfig(path=path))
    return _dedupe_probe_configs(configs)


def build_conditional_deep_probe_configs(include_post: bool = False) -> List[ProbeConfig]:
    configs = list(CONDITIONAL_DEEP_PROBE_CONFIGS)
    if include_post:
        configs.extend(POST_PROBE_CONFIGS)
    return _dedupe_probe_configs(configs)


def probe_candidate(
    base_url: str,
    probes: Iterable[Union[str, ProbeConfig]],
    timeout: float,
    verify_tls: bool,
    user_agent: str,
    max_bytes: int,
) -> Tuple[Dict[str, ProbeObservation], List[str]]:
    observations: Dict[str, ProbeObservation] = {}
    errors: List[str] = []

    for config in _coerce_probe_configs(probes):
        key = _observation_key(config.path, config.method, config.probe_name)
        observation = _fetch(
            base_url=base_url,
            config=config,
            timeout=timeout,
            verify_tls=verify_tls,
            user_agent=user_agent,
            max_bytes=max_bytes,
        )
        observations[key] = observation
        if observation.error:
            errors.append(f"{key}: {observation.error}")

    return observations, errors


def has_signal(observations: Dict[str, ProbeObservation]) -> bool:
    for observation in observations.values():
        if observation.status is not None:
            return True
        if observation.title or observation.js_files or observation.body_markers:
            return True
    return False


def _fetch(
    base_url: str,
    config: ProbeConfig,
    timeout: float,
    verify_tls: bool,
    user_agent: str,
    max_bytes: int,
) -> ProbeObservation:
    method = config.method.upper()
    path = _normalize_probe_path(config.path)
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request_headers = {"User-Agent": user_agent}
    if config.websocket_upgrade:
        request_headers.update(_build_websocket_upgrade_headers(url))
    request_headers.update(config.headers)
    request_data = config.body
    if request_data is None and method in {"POST", "PUT", "PATCH"}:
        request_data = b""
    request = Request(url, data=request_data, headers=request_headers, method=method)
    context = None
    if url.startswith("https://") and not verify_tls:
        context = ssl._create_unverified_context()

    headers: Dict[str, str] = {}
    header_order: List[str] = []
    status: Optional[int] = None
    final_url: Optional[str] = None
    raw_body = b""
    error: Optional[str] = None
    response_time_ms: Optional[float] = None

    started = time.perf_counter()
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            header_items = list(response.headers.items())
            status = response.getcode()
            headers = _normalize_headers(header_items)
            header_order = _extract_header_order(header_items)
            final_url = response.geturl()
            if _should_read_response_body(config, status):
                raw_body = response.read(max_bytes + 1)[:max_bytes]
        response_time_ms = (time.perf_counter() - started) * 1000.0
    except HTTPError as exc:
        header_items = list(exc.headers.items())
        status = exc.code
        headers = _normalize_headers(header_items)
        header_order = _extract_header_order(header_items)
        final_url = exc.geturl()
        if _should_read_response_body(config, status):
            raw_body = exc.read(max_bytes + 1)[:max_bytes]
        response_time_ms = (time.perf_counter() - started) * 1000.0
    except URLError as exc:
        error = str(exc.reason)
    except ssl.SSLError as exc:
        error = str(exc)
    except Exception as exc:  # pragma: no cover - defensive catch for live scans
        error = str(exc)

    text = _decode_body(raw_body)
    content_type = headers.get("content-type")
    error_text = _extract_error_text(text) if status is not None and status >= 400 else None
    has_stack_trace = _detect_stack_trace(text) if error_text else False
    favicon_hash = _compute_favicon_hash(path, status, content_type, raw_body)
    json_keys = _extract_json_keys(text, content_type)

    return ProbeObservation(
        path=path,
        url=url,
        method=method,
        probe_name=config.probe_name,
        status=status,
        final_url=final_url,
        response_time_ms=round(response_time_ms, 3) if response_time_ms is not None else None,
        headers=headers,
        header_order=header_order,
        content_type=content_type,
        body_length=len(raw_body),
        body_sha256=hashlib.sha256(raw_body).hexdigest() if raw_body else None,
        title=_extract_title(text),
        js_files=_extract_js_files(text),
        json_keys=json_keys,
        body_markers=_extract_markers(text),
        version_hints=_extract_versions(text, headers),
        cdp=_extract_cdp_facts(path, status, text, content_type),
        error_text=error_text,
        has_stack_trace=has_stack_trace,
        favicon_hash=favicon_hash,
        error=error,
    )


def _normalize_headers(items: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    return {key.lower(): value for key, value in items}


def _extract_header_order(items: Iterable[Tuple[str, str]]) -> List[str]:
    return [str(key).lower() for key, _ in items]


def _decode_body(raw_body: bytes) -> str:
    if not raw_body:
        return ""
    return raw_body.decode("utf-8", errors="ignore")


def _extract_title(text: str) -> Optional[str]:
    match = TITLE_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


def _extract_js_files(text: str) -> List[str]:
    files = sorted(set(SCRIPT_RE.findall(text)))
    return files


def _extract_json_keys(text: str, content_type: Optional[str]) -> List[str]:
    parsed = _parse_json_body(text, content_type)
    if parsed is None:
        parsed = _parse_socketio_open_packet(text)
    if parsed is None:
        return []

    if isinstance(parsed, dict):
        return sorted(str(key) for key in parsed.keys())
    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
        return sorted(str(key) for key in parsed[0].keys())
    return []


def _parse_json_body(text: str, content_type: Optional[str]):
    if not text:
        return None
    looks_json = False
    if content_type and "json" in content_type.lower():
        looks_json = True
    if text.lstrip().startswith("{") or text.lstrip().startswith("["):
        looks_json = True
    if not looks_json:
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _parse_socketio_open_packet(text: str):
    packet = (text or "").strip()
    if not packet.startswith("0{"):
        return None
    try:
        parsed = json.loads(packet[1:])
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    keys = {str(key).lower() for key in parsed}
    if "sid" not in keys or "upgrades" not in keys:
        return None
    return parsed


def _extract_cdp_facts(
    path: str,
    status: Optional[int],
    text: str,
    content_type: Optional[str],
) -> Dict[str, str]:
    if status != 200 or path not in {"/json/version", "/json/list", "/json"}:
        return {}

    parsed = _parse_json_body(text, content_type)
    documents = []
    if isinstance(parsed, dict):
        documents = [parsed]
    elif isinstance(parsed, list):
        documents = [item for item in parsed if isinstance(item, dict)]
    if not documents:
        return {}

    facts: Dict[str, str] = {}
    debugger_url_present = False
    for document in documents:
        browser = _first_text(document, "Browser", "browser")
        if browser:
            engine, chromium_version, headless = _parse_browser_field(browser)
            if engine:
                facts.setdefault("engine", engine)
            facts.setdefault("browser_family", "Chromium")
            if chromium_version:
                facts.setdefault("chromium_version", chromium_version)
            if headless is not None:
                facts.setdefault("headless", str(headless).lower())

        protocol_version = _first_text(document, "Protocol-Version", "protocolVersion")
        if protocol_version:
            facts.setdefault("protocol_version", protocol_version)

        v8_version = _first_text(document, "V8-Version", "v8Version")
        if v8_version:
            facts.setdefault("v8_version", v8_version)

        if "webSocketDebuggerUrl" in document:
            debugger_url_present = debugger_url_present or bool(
                document.get("webSocketDebuggerUrl")
            )

    if facts or debugger_url_present:
        facts["present"] = "true"
        facts.setdefault("browser_family", "Chromium")
        facts["debugger_url_present"] = str(debugger_url_present).lower()
        facts["ws_debugger_present"] = facts["debugger_url_present"]
    return facts


def _first_text(document: Dict[str, object], *keys: str) -> Optional[str]:
    for key in keys:
        value = document.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _parse_browser_field(value: str) -> Tuple[Optional[str], Optional[str], Optional[bool]]:
    if "/" in value:
        engine, version = value.split("/", 1)
    else:
        engine, version = value, ""
    engine = engine.strip() or None
    version = version.strip() or None
    lower_engine = (engine or "").lower()
    headless = True if "headless" in lower_engine else False if engine else None
    return engine, version, headless


def _extract_markers(text: str) -> List[str]:
    haystack = text.lower()
    found = [marker for marker in PRODUCT_MARKERS if marker in haystack]
    if _parse_socketio_open_packet(text):
        found.append("socketio_polling_handshake")
    if "novnc" in haystack:
        found.append("novnc_presence")
    if "websockify" in haystack:
        found.append("websockify_presence")
    return sorted(set(found))


def _extract_versions(text: str, headers: Dict[str, str]) -> List[str]:
    hints = set()
    hints.update(find_versions_near_markers(text))
    for key, value in headers.items():
        key_text = str(key).lower()
        if "version" in key_text or "openclaw" in key_text or "clawdbot" in key_text:
            hints.update(find_versions(str(value)))
        else:
            hints.update(find_versions_near_markers(str(value)))
    return sorted(hints, key=version_sort_key, reverse=True)


def _extract_error_text(text: str, max_length: int = 256) -> Optional[str]:
    if not text:
        return None
    stripped = HTML_TAG_RE.sub(" ", text)
    stripped = WHITESPACE_RE.sub(" ", stripped).strip()
    if not stripped:
        return None
    return stripped[:max_length]


def _detect_stack_trace(text: str) -> bool:
    if not text:
        return False
    return any(pattern.search(text) for pattern in STACK_TRACE_PATTERNS)


def _compute_favicon_hash(
    path: str,
    status: Optional[int],
    content_type: Optional[str],
    raw_body: bytes,
) -> Optional[int]:
    if path != "/favicon.ico" or status != 200 or not raw_body:
        return None

    normalized_content_type = (content_type or "").lower()
    if normalized_content_type:
        if "text/html" in normalized_content_type or "json" in normalized_content_type:
            return None
        if not any(
            token in normalized_content_type
            for token in ("icon", "image/", "octet-stream")
        ):
            return None
    elif raw_body.lstrip().startswith(b"<"):
        return None

    return _shodan_favicon_hash(raw_body)


def _shodan_favicon_hash(raw_favicon_bytes: bytes) -> int:
    return _murmurhash3_32(_encode_base64_with_newlines(raw_favicon_bytes))


def _encode_base64_with_newlines(raw_favicon_bytes: bytes) -> bytes:
    import base64

    return base64.encodebytes(raw_favicon_bytes)


def _murmurhash3_32(data: bytes, seed: int = 0) -> int:
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF

    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for block_start in range(0, nblocks * 4, 4):
        k1 = struct.unpack_from("<I", data, block_start)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail_index = nblocks * 4
    tail_size = length & 3
    k1 = 0
    if tail_size >= 3:
        k1 ^= data[tail_index + 2] << 16
    if tail_size >= 2:
        k1 ^= data[tail_index + 1] << 8
    if tail_size >= 1:
        k1 ^= data[tail_index]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def _coerce_probe_configs(probes: Iterable[Union[str, ProbeConfig]]) -> List[ProbeConfig]:
    configs = []
    for probe in probes:
        if isinstance(probe, ProbeConfig):
            configs.append(probe)
        else:
            configs.append(ProbeConfig(path=str(probe)))
    return _dedupe_probe_configs(configs)


def _dedupe_probe_configs(configs: Iterable[ProbeConfig]) -> List[ProbeConfig]:
    deduped: List[ProbeConfig] = []
    seen = set()
    for config in configs:
        method = config.method.upper()
        path = _normalize_probe_path(config.path)
        probe_name = (config.probe_name or "").strip().lower() or None
        key = (method, path, probe_name, bool(config.websocket_upgrade))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(
            ProbeConfig(
                path=path,
                method=method,
                probe_name=config.probe_name,
                websocket_upgrade=bool(config.websocket_upgrade),
                headers=dict(config.headers),
                body=config.body,
            )
        )
    return deduped


def _normalize_probe_path(path: str) -> str:
    path = str(path or "/").strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _observation_key(path: str, method: str, probe_name: Optional[str] = None) -> str:
    normalized_path = _normalize_probe_path(path)
    normalized_method = method.upper()
    prefix = f"{probe_name.upper()} " if probe_name else ""
    if normalized_method == "GET":
        return f"{prefix}{normalized_path}".strip()
    return f"{prefix}{normalized_method} {normalized_path}".strip()


def _build_websocket_upgrade_headers(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    origin_scheme = "https" if parsed.scheme == "https" else "http"
    host = parsed.netloc
    return {
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
        "Origin": f"{origin_scheme}://{host}",
    }


def _should_read_response_body(config: ProbeConfig, status: Optional[int]) -> bool:
    return not (config.websocket_upgrade and status == 101)
