import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse

from .discovery import score_passive_record
from .external import load_external_records
from .models import ScanTarget
from .shodan_meta import detect_platform, extract_banner_meta, generate_pivot_queries
from .versions import find_package_version, find_versions

DEFAULT_TLS_PORTS = {443, 8443, 9443, 18789}
MDNS_PRODUCT_MARKERS = (
    "openclaw",
    "clawdbot",
    "moltbot",
    "claw gateway",
    "openclaw-gw",
    "clawdbot-gw",
)


def load_targets(
    direct_targets: Optional[Sequence[str]] = None,
    targets_file: Optional[str] = None,
    shodan_file: Optional[str] = None,
    shodan_records: Optional[Sequence[dict]] = None,
    censys_file: Optional[str] = None,
    fofa_file: Optional[str] = None,
    ct_file: Optional[str] = None,
    probe_ports: Optional[Sequence[int]] = None,
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
        _append_shodan_targets(
            targets,
            _load_shodan_objects(Path(shodan_file)),
            "shodan",
            probe_ports=probe_ports,
        )

    if shodan_records:
        _append_shodan_targets(
            targets,
            shodan_records,
            "shodan_api",
            probe_ports=probe_ports,
        )

    if censys_file:
        _append_external_targets(
            targets,
            load_external_records(censys_file, "censys"),
            "censys",
            probe_ports=probe_ports,
        )

    if fofa_file:
        _append_external_targets(
            targets,
            load_external_records(fofa_file, "fofa"),
            "fofa",
            probe_ports=probe_ports,
        )

    if ct_file:
        _append_external_targets(
            targets,
            load_external_records(ct_file, "ct"),
            "ct",
            probe_ports=probe_ports,
        )

    deduped: Dict[str, ScanTarget] = {}
    for target in targets:
        key = "|".join([target.source, target.label] + target.candidates)
        deduped[key] = target

    return list(deduped.values())


def _append_shodan_targets(
    targets: List[ScanTarget],
    records: Iterable[dict],
    source: str,
    probe_ports: Optional[Sequence[int]] = None,
) -> None:
    for item in records:
        label = _shodan_label(item)
        scanner_meta = item.get("_openclaw_scanner") or {}
        banner_meta = extract_banner_meta(item)
        platform = detect_platform(banner_meta.os)
        mdns_fingerprint = _extract_mdns_fingerprint(item)
        discovery_meta = score_passive_record(item)
        targets.append(
            ScanTarget(
                label=label,
                source=source,
                candidates=_expand_candidates_for_ports(
                    _shodan_candidates(item),
                    probe_ports,
                ),
                metadata={
                    **{
                        key: item.get(key)
                        for key in ("ip_str", "port", "hostnames", "org", "ssl")
                        if key in item
                    },
                    **{
                        key: value
                        for key, value in {
                            "shodan_product": banner_meta.product,
                            "shodan_version": banner_meta.version,
                            "shodan_os": banner_meta.os,
                            "shodan_cpe": banner_meta.cpe,
                            "shodan_banner_hash": banner_meta.banner_hash,
                            "shodan_html_hash": banner_meta.html_hash,
                            "shodan_headers_hash": banner_meta.headers_hash,
                            "shodan_favicon_hash": banner_meta.favicon_hash,
                            "shodan_robots_hash": banner_meta.robots_hash,
                            "shodan_http_title": banner_meta.http_title,
                            "shodan_http_server": banner_meta.http_server,
                            "shodan_http_status": banner_meta.http_status,
                            "shodan_http_components": banner_meta.http_components,
                            "shodan_http_waf": banner_meta.http_waf,
                            "shodan_ssl_jarm": banner_meta.ssl_jarm,
                            "shodan_ssl_versions": banner_meta.ssl_versions,
                            "shodan_ssl_cert_fingerprint": banner_meta.ssl_cert_fingerprint,
                            "shodan_ssl_cert_subject_cn": banner_meta.ssl_cert_subject_cn,
                            "shodan_ssl_cert_issuer_o": banner_meta.ssl_cert_issuer_o,
                            "shodan_vulns": banner_meta.vulns,
                            "shodan_module": banner_meta.shodan_module,
                            "platform": platform,
                            "shodan_pivot_queries": generate_pivot_queries(banner_meta),
                            "discovery_confidence": discovery_meta.get(
                                "discovery_confidence"
                            ),
                            "discovery_sources": discovery_meta.get("discovery_sources"),
                            "passive_noise_downgraded": discovery_meta.get(
                                "passive_noise_downgraded"
                            ),
                            "passive_noise_confidence_cap": discovery_meta.get(
                                "passive_noise_confidence_cap"
                            ),
                            "passive_noise_reasons": discovery_meta.get(
                                "passive_noise_reasons"
                            ),
                            "passive_noise_matched_products": discovery_meta.get(
                                "passive_noise_matched_products"
                            ),
                            "mdns_service_types": _sorted_strings(
                                mdns_fingerprint.get("service_types", [])
                            ),
                            "mdns_instance_names": _sorted_strings(
                                mdns_fingerprint.get("instance_names", [])
                            ),
                            "mdns_txt_records": mdns_fingerprint.get("txt_records"),
                            "mdns_advertised_ports": mdns_fingerprint.get("advertised_ports"),
                            "mdns_hostname": mdns_fingerprint.get("hostname"),
                            "mdns_version": mdns_fingerprint.get("version"),
                            "mdns_version_source": mdns_fingerprint.get("version_source"),
                            "mdns_devtools_revision": mdns_fingerprint.get("devtools_revision"),
                            "mdns_product_markers": _sorted_strings(
                                mdns_fingerprint.get("product_markers", [])
                            ),
                        }.items()
                        if value not in (None, [], {}, "")
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


def _append_external_targets(
    targets: List[ScanTarget],
    records: Iterable[dict],
    source: str,
    probe_ports: Optional[Sequence[int]] = None,
) -> None:
    for item in records:
        label = _shodan_label(item)
        banner_meta = extract_banner_meta(item)
        normalized = item.get("_openclaw_normalized") or {}
        engine = str(normalized.get("engine") or source)
        targets.append(
            ScanTarget(
                label=label,
                source=source,
                candidates=_expand_candidates_for_ports(
                    _shodan_candidates(item),
                    probe_ports,
                ),
                metadata={
                    **_external_metadata(engine, banner_meta, normalized),
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


def _external_metadata(engine: str, banner_meta, normalized: Dict[str, Any]) -> Dict[str, Any]:
    prefix = engine.lower().strip() or "external"
    metadata = {
        "external_engine": prefix,
        "passive_http_title": banner_meta.http_title,
        "passive_http_status": banner_meta.http_status,
        "passive_http_server": banner_meta.http_server,
        "passive_favicon_hash": banner_meta.favicon_hash,
        "passive_ssl_jarm": banner_meta.ssl_jarm,
        "passive_tls_subject_cn": banner_meta.ssl_cert_subject_cn,
        "discovery_confidence": normalized.get("discovery_confidence"),
        "discovery_sources": normalized.get("discovery_sources"),
        "passive_noise_downgraded": normalized.get("passive_noise_downgraded"),
        "passive_noise_confidence_cap": normalized.get("passive_noise_confidence_cap"),
        "passive_noise_reasons": normalized.get("passive_noise_reasons"),
        "passive_noise_matched_products": normalized.get(
            "passive_noise_matched_products"
        ),
    }
    metadata.update(
        {
            f"{prefix}_http_title": banner_meta.http_title,
            f"{prefix}_http_status": banner_meta.http_status,
            f"{prefix}_http_server": banner_meta.http_server,
            f"{prefix}_favicon_hash": banner_meta.favicon_hash,
            f"{prefix}_ssl_jarm": banner_meta.ssl_jarm,
            f"{prefix}_tls_subject_cn": banner_meta.ssl_cert_subject_cn,
        }
    )
    for key, value in normalized.items():
        if key in {
            "engine",
            "discovery_confidence",
            "discovery_sources",
            "passive_noise_downgraded",
            "passive_noise_confidence_cap",
            "passive_noise_reasons",
            "passive_noise_matched_products",
        }:
            continue
        metadata_key = key if key.startswith(f"{prefix}_") else f"{prefix}_{key}"
        metadata[metadata_key] = value
    return {
        key: value
        for key, value in metadata.items()
        if value not in (None, [], {}, "")
    }


def _expand_candidates_for_ports(
    candidates: Sequence[str],
    probe_ports: Optional[Sequence[int]],
) -> List[str]:
    deduped = list(dict.fromkeys(candidates))
    if not probe_ports:
        return deduped

    expanded = list(deduped)
    hosts = []
    for candidate in deduped:
        parsed = urlparse(candidate)
        if parsed.hostname:
            hosts.append(parsed.hostname)
    for host in dict.fromkeys(hosts):
        authority_host = _format_authority_host(host)
        for port in probe_ports:
            if port <= 0:
                continue
            authority = f"{authority_host}:{port}"
            schemes = ("https", "http") if port in DEFAULT_TLS_PORTS else ("http", "https")
            for scheme in schemes:
                expanded.append(f"{scheme}://{authority}")
    return list(dict.fromkeys(expanded))


def _format_authority_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


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
    normalized = item.get("_openclaw_normalized") or {}
    protocol = str(normalized.get("protocol") or "").lower()
    if protocol in {"http", "https"}:
        return protocol
    if item.get("ssl"):
        return "https"
    if port in DEFAULT_TLS_PORTS:
        return "https"
    return "http"


def _extract_gateway_port(item: dict) -> Optional[int]:
    mdns_fingerprint = _extract_mdns_fingerprint(item)
    advertised_ports = mdns_fingerprint.get("advertised_ports", [])
    if 18789 in advertised_ports:
        return 18789
    if advertised_ports:
        return int(advertised_ports[0])
    return None


def _port_from_service_name(value: str) -> Optional[int]:
    prefix = value.split("/", 1)[0]
    return int(prefix) if prefix.isdigit() else None


def _extract_mdns_fingerprint(item: dict) -> Dict[str, Any]:
    mdns = item.get("mdns") or {}
    services = mdns.get("services") or {}
    answers = mdns.get("answers") or {}

    if not services:
        return {}

    service_types = set()
    instance_names = []
    txt_records: Dict[str, str] = {}
    advertised_ports = set()
    product_markers = set()
    version = None
    version_source = None
    devtools_revision = None
    hostname = _normalize_mdns_hostname(mdns.get("hostname"))

    for service_name, service in services.items():
        lower_service_name = str(service_name).lower()
        parsed_port = _port_from_service_name(str(service_name))
        if parsed_port is not None:
            advertised_ports.add(parsed_port)

        if "openclaw-gw" in lower_service_name:
            service_types.add("_openclaw-gw._tcp.local")
        if "clawdbot-gw" in lower_service_name:
            service_types.add("_clawdbot-gw._tcp.local")
        if "moltbot" in lower_service_name:
            service_types.add("_moltbot._tcp.local")

        instance_name = service.get("name")
        if isinstance(instance_name, str) and instance_name:
            instance_names.append(instance_name)

        ptr_value = service.get("ptr")
        if isinstance(ptr_value, str) and ptr_value:
            service_types.add(ptr_value)

        for entry in service.get("data", []):
            if not isinstance(entry, str) or not entry:
                continue
            if "=" in entry:
                key, _, value = entry.partition("=")
                key = key.strip().lower()
                value = value.strip()
                txt_records[key] = value
                if key == "gatewayport" and value.isdigit():
                    advertised_ports.add(int(value))
                if devtools_revision is None:
                    devtools_revision = _extract_devtools_revision(value)
                if version is None:
                    package_version = find_package_version(value)
                    if package_version:
                        version = package_version
                        version_source = (
                            "cli_path_package"
                            if key in {"clipath", "cli_path", "cli-path"}
                            else "package_metadata"
                        )
                    else:
                        versions = find_versions(value)
                        if versions:
                            version = versions[0]
                            version_source = "txt"
                if hostname is None and key in {"lanhost", "hostname"}:
                    hostname = _normalize_mdns_hostname(value)
            else:
                txt_records[entry.strip().lower()] = ""

    for record_values in answers.values():
        if not isinstance(record_values, list):
            continue
        for value in record_values:
            if isinstance(value, str) and value:
                service_types.add(value)

    corpus = " ".join(
        list(service_types)
        + instance_names
        + list(txt_records.keys())
        + list(txt_records.values())
    ).lower()
    for marker in MDNS_PRODUCT_MARKERS:
        if marker in corpus:
            product_markers.add(marker)

    return {
        "service_types": sorted(service_types),
        "instance_names": sorted(set(instance_names)),
        "txt_records": dict(sorted(txt_records.items())),
        "advertised_ports": sorted(advertised_ports),
        "hostname": hostname,
        "version": version,
        "version_source": version_source,
        "devtools_revision": devtools_revision,
        "product_markers": sorted(product_markers),
    }


def _extract_devtools_revision(value: str) -> Optional[int]:
    marker = "devtools-protocol@0.0."
    lower = value.lower()
    index = lower.find(marker)
    if index < 0:
        return None
    start = index + len(marker)
    digits = []
    for char in value[start:]:
        if not char.isdigit():
            break
        digits.append(char)
    return int("".join(digits)) if digits else None


def _normalize_mdns_hostname(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    return str(value).rstrip(".")


def _sorted_strings(values: Iterable[Any]) -> List[str]:
    return sorted(str(value) for value in values if value not in (None, ""))
