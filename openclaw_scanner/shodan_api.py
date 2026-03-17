import json
import os
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


API_BASE_URL = "https://api.shodan.io"
DEFAULT_DOTENV_PATHS = (Path(".env"), Path("openclaw_scanner/.env"))


class ShodanAPIError(RuntimeError):
    """Raised when the Shodan API request fails."""


def resolve_shodan_api_key(
    explicit_key: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    dotenv_paths: Optional[Sequence[Path]] = None,
) -> Optional[str]:
    if explicit_key and explicit_key.strip():
        return explicit_key.strip()

    env_map = dict(os.environ if env is None else env)
    env_value = env_map.get("SHODAN_API_KEY")
    if env_value and env_value.strip():
        return env_value.strip()

    for path in dotenv_paths or DEFAULT_DOTENV_PATHS:
        value = _read_dotenv_value(Path(path), "SHODAN_API_KEY")
        if value:
            return value

    return None


def search_shodan(
    query: str,
    api_key: str,
    pages: int = 1,
    fields: Optional[str] = None,
    minify: bool = False,
    timeout: float = 10.0,
    user_agent: str = "openclaw-scanner/0.1",
) -> Dict[str, Any]:
    pages = max(int(pages), 1)
    aggregated_matches: List[Dict[str, Any]] = []
    total: Optional[int] = None
    pages_fetched = 0

    for page in range(1, pages + 1):
        params = {
            "key": api_key,
            "query": query,
            "page": page,
            "minify": str(bool(minify)).lower(),
        }
        if fields:
            params["fields"] = fields

        payload = _request_json(
            path="/shodan/host/search",
            params=params,
            timeout=timeout,
            user_agent=user_agent,
        )
        matches = list(payload.get("matches", []))
        total = payload.get("total", total)
        pages_fetched += 1

        for match in matches:
            if not isinstance(match, dict):
                continue
            annotated = dict(match)
            annotated["_openclaw_scanner"] = {
                "query": query,
                "page": page,
                "minify": bool(minify),
                "fields": fields,
            }
            aggregated_matches.append(annotated)

        # Shodan returns 100 results per page. A short page means we're done.
        if len(matches) < 100:
            break

    return {
        "query": query,
        "total": total,
        "pages_requested": pages,
        "pages_fetched": pages_fetched,
        "matches": aggregated_matches,
    }


def _request_json(
    path: str,
    params: Mapping[str, Any],
    timeout: float,
    user_agent: str,
) -> Dict[str, Any]:
    query = urlencode(params)
    url = f"{API_BASE_URL}{path}?{query}"
    request = Request(url, headers={"User-Agent": user_agent})

    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except HTTPError as exc:
        message = exc.read().decode("utf-8", errors="ignore").strip()
        raise ShodanAPIError(
            f"Shodan API returned HTTP {exc.code}: {message or exc.reason}"
        ) from exc
    except URLError as exc:
        raise ShodanAPIError(f"Shodan API request failed: {exc.reason}") from exc

    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ShodanAPIError("Shodan API returned invalid JSON.") from exc


def _read_dotenv_value(path: Path, key: str) -> Optional[str]:
    if not path.exists():
        return None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        candidate_key, value = line.split("=", 1)
        candidate_key = candidate_key.strip()
        if candidate_key != key:
            continue

        cleaned = value.strip().strip("'").strip('"')
        return cleaned or None

    return None
