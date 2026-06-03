import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from .discovery import NAME_INDICATORS, safe_headers, score_passive_record


CT_NAME_SPLIT_RE = re.compile(r"[\s,;]+")


def load_external_records(path: str, engine: str) -> List[Dict[str, Any]]:
    objects = _load_export_objects(Path(path))
    normalized_engine = engine.lower().strip()
    if normalized_engine == "censys":
        return _normalize_censys_objects(objects)
    if normalized_engine == "fofa":
        return _normalize_fofa_objects(objects)
    if normalized_engine == "ct":
        return _normalize_ct_objects(objects)
    raise ValueError(f"unsupported external import engine: {engine}")


def _load_export_objects(path: Path) -> List[Dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]

    raw = path.read_text(encoding="utf-8")
    stripped = raw.strip()
    if not stripped:
        return []

    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return _load_json_lines(raw)
        return _objects_from_json_export(data)

    return _load_json_lines(raw)


def _objects_from_json_export(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []

    if isinstance(data.get("matches"), list):
        return [item for item in data["matches"] if isinstance(item, dict)]
    if isinstance(data.get("hits"), list):
        return [item for item in data["hits"] if isinstance(item, dict)]
    if isinstance(data.get("results"), list):
        fields = data.get("fields")
        if isinstance(fields, list):
            rows = []
            for row in data["results"]:
                if isinstance(row, list):
                    rows.append(
                        {
                            str(field): row[index] if index < len(row) else None
                            for index, field in enumerate(fields)
                        }
                    )
                elif isinstance(row, dict):
                    rows.append(row)
            return rows
        return [item for item in data["results"] if isinstance(item, dict)]
    return [data]


def _load_json_lines(raw: str) -> List[Dict[str, Any]]:
    objects = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        if isinstance(item, dict):
            objects.append(item)
    return objects


def _normalize_censys_objects(objects: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    records = []
    for item in objects:
        services = item.get("services")
        if isinstance(services, list):
            for service in services:
                if isinstance(service, dict):
                    record = _normalize_censys_service(item, service)
                    if record:
                        records.append(record)
            continue

        record = _normalize_censys_service(item, item)
        if record:
            records.append(record)
    return records


def _normalize_censys_service(
    host_record: Dict[str, Any],
    service: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    host = _first_value(
        service,
        host_record,
        ("ip", "ip_str", "host", "hostname", "domain", "name"),
    )
    port = _optional_int(
        _first_value(
            service,
            host_record,
            ("port", "service_port", "services.port"),
        )
    )
    if not host:
        return None

    http_response = _censys_http_response(service)
    tls_data = _censys_tls_data(service)
    protocol = _infer_protocol(
        _first_value(
            service,
            host_record,
            ("scheme", "protocol", "service_name", "extended_service_name"),
        ),
        port,
        tls_data,
    )
    record = _build_record(
        engine="censys",
        host=str(host),
        port=port,
        protocol=protocol,
        title=_first_value(http_response, service, ("html_title", "title")),
        body=_first_value(http_response, service, ("body", "html")),
        headers=safe_headers(http_response.get("headers") or service.get("headers")),
        status=_optional_int(
            _first_value(http_response, service, ("status_code", "status"))
        ),
        server=_first_value(http_response, service, ("server",)),
        favicon_hash=_optional_int(
            _first_value(http_response, service, ("favicon_hash", "favicon.mmh3"))
        ),
        jarm=_first_value(tls_data, service, ("jarm", "tls.jarm")),
        cert_subject_cn=_first_value(
            tls_data,
            service,
            ("subject_common_name", "subject.cn", "common_name"),
        ),
        cert_names=_extract_censys_cert_names(tls_data),
        raw_metadata={
            "censys_service_name": _first_value(
                service,
                host_record,
                ("service_name", "extended_service_name"),
            ),
            "censys_transport": _first_value(
                service,
                host_record,
                ("transport_protocol", "transport"),
            ),
        },
    )
    return record


def _normalize_fofa_objects(objects: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    records = []
    for item in objects:
        host_value = _first_value(item, item, ("host", "ip", "domain", "hostname"))
        parsed = _parse_host_value(host_value)
        host = parsed["host"] or _first_value(item, item, ("ip", "domain", "hostname"))
        port = _optional_int(_first_value(item, item, ("port",))) or parsed["port"]
        protocol = _infer_protocol(
            parsed["scheme"] or _first_value(item, item, ("protocol", "scheme")),
            port,
            item.get("tls") or item.get("ssl"),
        )
        if not host:
            continue
        records.append(
            _build_record(
                engine="fofa",
                host=str(host),
                port=port,
                protocol=protocol,
                title=_first_value(item, item, ("title", "http_title")),
                body=_first_value(item, item, ("body", "html", "banner")),
                headers=safe_headers(item.get("headers")),
                status=_optional_int(_first_value(item, item, ("status", "status_code"))),
                server=_first_value(item, item, ("server",)),
                favicon_hash=_optional_int(
                    _first_value(item, item, ("favicon_hash", "icon_hash"))
                ),
                jarm=_first_value(item, item, ("jarm", "tls_jarm", "ssl_jarm")),
                cert_subject_cn=_first_value(
                    item,
                    item,
                    ("cert_subject_cn", "subject_cn", "common_name"),
                ),
                cert_names=_extract_listish(
                    _first_value(item, item, ("cert_names", "san", "sans", "dns_names"))
                ),
                raw_metadata={
                    "fofa_protocol": _first_value(item, item, ("protocol", "scheme")),
                    "fofa_host": str(host_value) if host_value else None,
                },
            )
        )
    return records


def _normalize_ct_objects(objects: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    records = []
    for item in objects:
        names = _extract_ct_names(item)
        indicator_names = [
            name
            for name in names
            if any(marker in name.lower() for marker in NAME_INDICATORS)
        ]
        for name in indicator_names[:20]:
            host = _normalize_ct_hostname(name)
            if not host:
                continue
            records.append(
                _build_record(
                    engine="ct",
                    host=host,
                    port=None,
                    protocol="https",
                    title=None,
                    body=" ".join(names),
                    headers={},
                    status=None,
                    server=None,
                    favicon_hash=None,
                    jarm=None,
                    cert_subject_cn=_first_value(
                        item,
                        item,
                        ("common_name", "cn", "subject_common_name"),
                    ),
                    cert_names=names,
                    raw_metadata={
                        "ct_indicator_names": indicator_names,
                        "ct_name_count": len(names),
                    },
                )
            )
    return records


def _build_record(
    engine: str,
    host: str,
    port: Optional[int],
    protocol: str,
    title: Any,
    body: Any,
    headers: Dict[str, str],
    status: Optional[int],
    server: Any,
    favicon_hash: Optional[int],
    jarm: Any,
    cert_subject_cn: Any,
    cert_names: Iterable[str],
    raw_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    http: Dict[str, Any] = {
        key: value
        for key, value in {
            "title": _optional_str(title),
            "html": _optional_str(body),
            "headers": headers,
            "status": status,
            "server": _optional_str(server),
        }.items()
        if value not in (None, "", {}, [])
    }
    if favicon_hash is not None:
        http["favicon"] = {"hash": favicon_hash}

    cert_names_list = sorted(set(str(value) for value in cert_names if value))
    ssl_data: Dict[str, Any] = {}
    if jarm:
        ssl_data["jarm"] = str(jarm)
    if cert_subject_cn or cert_names_list:
        ssl_data["cert"] = {
            "subject": {"CN": _optional_str(cert_subject_cn)}
            if cert_subject_cn
            else {},
            "san": {"dns": cert_names_list} if cert_names_list else {},
        }

    record = {
        "ip_str": host,
        "port": port,
        "transport": "tcp",
        "http": http,
        "ssl": ssl_data,
        "_openclaw_normalized": {
            "engine": engine,
            "protocol": protocol,
            **{
                key: value
                for key, value in raw_metadata.items()
                if value not in (None, "", {}, [])
            },
        },
    }
    record["_openclaw_normalized"].update(score_passive_record(record))
    return record


def _censys_http_response(service: Dict[str, Any]) -> Dict[str, Any]:
    http = service.get("http") or {}
    response = http.get("response") if isinstance(http, dict) else None
    if isinstance(response, dict):
        return response
    return http if isinstance(http, dict) else {}


def _censys_tls_data(service: Dict[str, Any]) -> Dict[str, Any]:
    tls = service.get("tls") or {}
    if not isinstance(tls, dict):
        return {}
    leaf_data = (
        tls.get("certificates", {})
        .get("leaf_data", {})
        if isinstance(tls.get("certificates"), dict)
        else {}
    )
    subject = leaf_data.get("subject", {}) if isinstance(leaf_data, dict) else {}
    names = leaf_data.get("names", []) if isinstance(leaf_data, dict) else []
    result = dict(tls)
    if subject:
        common_name = subject.get("common_name")
        if isinstance(common_name, list):
            common_name = common_name[0] if common_name else None
        result["subject_common_name"] = common_name
    if names:
        result["names"] = names
    return result


def _extract_censys_cert_names(tls_data: Dict[str, Any]) -> List[str]:
    return _extract_listish(
        tls_data.get("names")
        or tls_data.get("dns_names")
        or tls_data.get("san")
    )


def _extract_ct_names(item: Dict[str, Any]) -> List[str]:
    values = []
    for key in (
        "name_value",
        "common_name",
        "cn",
        "dns_names",
        "san",
        "sans",
        "subject_alt_names",
    ):
        values.extend(_extract_listish(item.get(key)))
    subject = item.get("subject")
    if isinstance(subject, dict):
        values.extend(
            _extract_listish(
                subject.get("common_name") or subject.get("CN") or subject.get("cn")
            )
        )
    result = []
    for value in values:
        for chunk in CT_NAME_SPLIT_RE.split(str(value)):
            chunk = chunk.strip().strip(".")
            if chunk:
                result.append(chunk)
    return sorted(set(result))


def _normalize_ct_hostname(name: str) -> Optional[str]:
    cleaned = name.strip().strip(".").lower()
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    if not cleaned or "/" in cleaned or "@" in cleaned:
        return None
    return cleaned


def _parse_host_value(value: Any) -> Dict[str, Any]:
    if not value:
        return {"scheme": None, "host": None, "port": None}
    raw = str(value).strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return {
        "scheme": parsed.scheme or None,
        "host": parsed.hostname,
        "port": parsed.port,
    }


def _infer_protocol(value: Any, port: Optional[int], tls_data: Any) -> str:
    protocol = str(value or "").lower()
    if protocol in {"https", "tls"} or "https" in protocol or "ssl" in protocol:
        return "https"
    if protocol == "http":
        return "http"
    if tls_data:
        return "https"
    if port in {443, 8443, 9443, 18789}:
        return "https"
    return "http"


def _first_value(
    primary: Dict[str, Any],
    fallback: Dict[str, Any],
    keys: Iterable[str],
) -> Any:
    for key in keys:
        for source in (primary, fallback):
            value = _nested_get(source, key)
            if value not in (None, "", [], {}):
                return value
    return None


def _nested_get(source: Dict[str, Any], key: str) -> Any:
    if key in source:
        return source[key]
    cursor: Any = source
    for part in key.split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            return None
        cursor = cursor[part]
    return cursor


def _extract_listish(value: Any) -> List[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    if isinstance(value, tuple):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def _optional_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_str(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    return str(value)
