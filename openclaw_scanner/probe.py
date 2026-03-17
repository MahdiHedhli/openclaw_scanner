import hashlib
import json
import re
import ssl
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from .models import ProbeObservation

DEFAULT_PROBE_PATHS = [
    "/",
    "/login",
    "/api",
    "/api/version",
    "/api/status",
    "/api/health",
    "/health",
    "/status",
    "/api/doesnotexist",
]

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

VERSION_TOKEN = r"20\d{2}\.\d+\.\d+(?:-[A-Za-z0-9]+)?"

VERSION_PATTERNS = [
    re.compile(
        rf"(?<![0-9A-Za-z])"
        r"(?:openclaw|clawdbot|moltbot|gateway|version|release|build)"
        r"[^0-9]{0,24}"
        rf"({VERSION_TOKEN})"
        rf"(?=$|[^0-9A-Za-z])",
        re.IGNORECASE,
    )
]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SCRIPT_RE = re.compile(
    r"<script[^>]+src=[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']",
    re.IGNORECASE,
)


def probe_candidate(
    base_url: str,
    paths: Iterable[str],
    timeout: float,
    verify_tls: bool,
    user_agent: str,
    max_bytes: int,
) -> Tuple[Dict[str, ProbeObservation], List[str]]:
    observations: Dict[str, ProbeObservation] = {}
    errors: List[str] = []

    for path in paths:
        observation = _fetch(
            base_url=base_url,
            path=path,
            timeout=timeout,
            verify_tls=verify_tls,
            user_agent=user_agent,
            max_bytes=max_bytes,
        )
        observations[path] = observation
        if observation.error:
            errors.append(f"{path}: {observation.error}")

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
    path: str,
    timeout: float,
    verify_tls: bool,
    user_agent: str,
    max_bytes: int,
) -> ProbeObservation:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request = Request(url, headers={"User-Agent": user_agent})
    context = None
    if url.startswith("https://") and not verify_tls:
        context = ssl._create_unverified_context()

    headers: Dict[str, str] = {}
    status: Optional[int] = None
    final_url: Optional[str] = None
    raw_body = b""
    error: Optional[str] = None

    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            status = response.getcode()
            headers = _normalize_headers(response.headers.items())
            final_url = response.geturl()
            raw_body = response.read(max_bytes + 1)[:max_bytes]
    except HTTPError as exc:
        status = exc.code
        headers = _normalize_headers(exc.headers.items())
        final_url = exc.geturl()
        raw_body = exc.read(max_bytes + 1)[:max_bytes]
    except URLError as exc:
        error = str(exc.reason)
    except ssl.SSLError as exc:
        error = str(exc)
    except Exception as exc:  # pragma: no cover - defensive catch for live scans
        error = str(exc)

    text = _decode_body(raw_body)
    content_type = headers.get("content-type")

    return ProbeObservation(
        path=path,
        url=url,
        status=status,
        final_url=final_url,
        headers=headers,
        content_type=content_type,
        body_length=len(raw_body),
        body_sha256=hashlib.sha256(raw_body).hexdigest() if raw_body else None,
        title=_extract_title(text),
        js_files=_extract_js_files(text),
        json_keys=_extract_json_keys(text, content_type),
        body_markers=_extract_markers(text),
        version_hints=_extract_versions(text, headers),
        error=error,
    )


def _normalize_headers(items: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    return {key.lower(): value for key, value in items}


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
    if not text:
        return []
    looks_json = False
    if content_type and "json" in content_type.lower():
        looks_json = True
    if text.lstrip().startswith("{") or text.lstrip().startswith("["):
        looks_json = True
    if not looks_json:
        return []

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []

    if isinstance(parsed, dict):
        return sorted(str(key) for key in parsed.keys())
    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
        return sorted(str(key) for key in parsed[0].keys())
    return []


def _extract_markers(text: str) -> List[str]:
    haystack = text.lower()
    found = [marker for marker in PRODUCT_MARKERS if marker in haystack]
    return sorted(set(found))


def _extract_versions(text: str, headers: Dict[str, str]) -> List[str]:
    hints = set()
    combined = "\n".join(
        [text]
        + [str(value) for value in headers.values()]
        + [str(key) for key in headers.keys()]
    )
    for pattern in VERSION_PATTERNS:
        for match in pattern.findall(combined):
            if isinstance(match, tuple):
                match = match[0]
            hints.add(match.lstrip("v"))
    return sorted(hints)
