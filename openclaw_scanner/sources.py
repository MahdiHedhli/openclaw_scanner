import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse

from .models import ScanTarget

DEFAULT_TLS_PORTS = {443, 8443, 9443, 18789}


def load_targets(
    direct_targets: Optional[Sequence[str]] = None,
    targets_file: Optional[str] = None,
    shodan_file: Optional[str] = None,
    shodan_records: Optional[Sequence[dict]] = None,
) -> List[ScanTarget]:
    targets: List[ScanTarget] = []

    for value in direct_targets or []:
        targets.append(
            ScanTarget(
                label=value.strip(),
                source="direct",
                candidates=_target_candidates(value.strip()),
            )
        )

    if targets_file:
        for line in Path(targets_file).read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            targets.append(
                ScanTarget(
                    label=value,
                    source="targets_file",
                    candidates=_target_candidates(value),
                )
            )

    if shodan_file:
        _append_shodan_targets(targets, _load_shodan_objects(Path(shodan_file)), "shodan")

    if shodan_records:
        _append_shodan_targets(targets, shodan_records, "shodan_api")

    deduped: Dict[str, ScanTarget] = {}
    for target in targets:
        key = "|".join([target.source, target.label] + target.candidates)
        deduped[key] = target

    return list(deduped.values())


def _append_shodan_targets(
    targets: List[ScanTarget],
    records: Iterable[dict],
    source: str,
) -> None:
    for item in records:
        label = _shodan_label(item)
        scanner_meta = item.get("_openclaw_scanner") or {}
        targets.append(
            ScanTarget(
                label=label,
                source=source,
                candidates=_shodan_candidates(item),
                metadata={
                    **{
                        key: item.get(key)
                        for key in ("ip_str", "port", "hostnames", "org", "ssl")
                        if key in item
                    },
                    **(
                        {"gateway_port": gateway_port}
                        if (gateway_port := _extract_gateway_port(item)) is not None
                        else {}
                    ),
                    **(
                        {"shodan_query": scanner_meta.get("query")}
                        if scanner_meta.get("query")
                        else {}
                    ),
                    **(
                        {"shodan_page": scanner_meta.get("page")}
                        if scanner_meta.get("page") is not None
                        else {}
                    ),
                },
                raw_record=item,
            )
        )


def _target_candidates(value: str) -> List[str]:
    if not value:
        return []

    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        return [value.rstrip("/")]

    stripped = value.rstrip("/")
    return [f"https://{stripped}", f"http://{stripped}"]


def _load_shodan_objects(path: Path) -> Iterable[dict]:
    raw = path.read_text(encoding="utf-8")
    stripped = raw.strip()
    if not stripped:
        return []

    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return _load_json_lines(raw)
        if isinstance(data, dict) and isinstance(data.get("matches"), list):
            return data["matches"]
        return [data]

    if stripped.startswith("["):
        data = json.loads(stripped)
        return data if isinstance(data, list) else [data]

    return _load_json_lines(raw)


def _load_json_lines(raw: str) -> List[dict]:
    objects = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        objects.append(json.loads(line))
    return objects


def _shodan_label(item: dict) -> str:
    ip_str = item.get("ip_str") or item.get("ip")
    port = _extract_gateway_port(item) or item.get("port")
    if ip_str and port:
        return f"{ip_str}:{port}"
    return ip_str or str(port) or "unknown-shodan-target"


def _shodan_candidates(item: dict) -> List[str]:
    host = item.get("ip_str") or item.get("ip")
    port = _extract_gateway_port(item) or item.get("port")
    if not host:
        return []

    if port:
        authority = f"{host}:{port}"
    else:
        authority = host

    preferred_scheme = _infer_shodan_scheme(item)
    alternate_scheme = "http" if preferred_scheme == "https" else "https"
    return [f"{preferred_scheme}://{authority}", f"{alternate_scheme}://{authority}"]


def _infer_shodan_scheme(item: dict) -> str:
    port = _extract_gateway_port(item) or item.get("port")
    if item.get("ssl"):
        return "https"
    if port in DEFAULT_TLS_PORTS:
        return "https"
    return "http"


def _extract_gateway_port(item: dict) -> Optional[int]:
    mdns = item.get("mdns") or {}
    services = mdns.get("services") or {}

    for service_name, service in services.items():
        parsed_port = _port_from_service_name(service_name)
        if parsed_port is not None:
            return parsed_port

        for entry in service.get("data", []):
            if isinstance(entry, str) and entry.startswith("gatewayPort="):
                _, _, value = entry.partition("=")
                if value.isdigit():
                    return int(value)

    return None


def _port_from_service_name(value: str) -> Optional[int]:
    prefix = value.split("/", 1)[0]
    return int(prefix) if prefix.isdigit() else None
