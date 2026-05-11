from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class ShodanBannerMeta:
    ip_str: str = ""
    port: int = 0
    transport: str = "tcp"
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    os: Optional[str] = None
    banner_hash: Optional[int] = None
    html_hash: Optional[int] = None
    headers_hash: Optional[int] = None
    favicon_hash: Optional[int] = None
    robots_hash: Optional[int] = None
    http_title: Optional[str] = None
    http_server: Optional[str] = None
    http_status: Optional[int] = None
    http_components: Dict[str, Any] = field(default_factory=dict)
    http_waf: Optional[str] = None
    ssl_cert_subject_cn: Optional[str] = None
    ssl_cert_issuer_o: Optional[str] = None
    ssl_cert_fingerprint: Optional[str] = None
    ssl_cert_serial: Optional[str] = None
    ssl_cert_pubkey_bits: Optional[int] = None
    ssl_cert_pubkey_type: Optional[str] = None
    ssl_cert_expired: Optional[bool] = None
    ssl_versions: List[str] = field(default_factory=list)
    ssl_cipher: Optional[str] = None
    ssl_jarm: Optional[str] = None
    vulns: List[str] = field(default_factory=list)
    org: Optional[str] = None
    asn: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    shodan_module: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def extract_banner_meta(banner: Dict[str, Any]) -> ShodanBannerMeta:
    http = banner.get("http", {}) or {}
    ssl_data = banner.get("ssl", {}) or {}
    ssl_cert = ssl_data.get("cert", {}) or {}
    ssl_subject = ssl_cert.get("subject", {}) or {}
    ssl_issuer = ssl_cert.get("issuer", {}) or {}
    ssl_pubkey = ssl_cert.get("pubkey", {}) or {}
    shodan_meta = banner.get("_shodan", {}) or {}
    favicon = http.get("favicon", {}) or {}
    raw_vulns = banner.get("vulns", {}) or {}

    return ShodanBannerMeta(
        ip_str=banner.get("ip_str", "") or "",
        port=int(banner.get("port", 0) or 0),
        transport=str(banner.get("transport", "tcp") or "tcp"),
        product=_as_optional_str(banner.get("product")),
        version=_as_optional_str(banner.get("version")),
        cpe=[str(value) for value in banner.get("cpe", []) or [] if value],
        os=_as_optional_str(banner.get("os")),
        banner_hash=_as_optional_int(banner.get("hash")),
        html_hash=_as_optional_int(http.get("html_hash")),
        headers_hash=_as_optional_int(http.get("headers_hash")),
        favicon_hash=_extract_favicon_hash(http),
        robots_hash=_as_optional_int(http.get("robots_hash")),
        http_title=_as_optional_str(http.get("title")),
        http_server=_as_optional_str(http.get("server")),
        http_status=_as_optional_int(http.get("status")),
        http_components=http.get("components", {}) or {},
        http_waf=_as_optional_str(http.get("waf")),
        ssl_cert_subject_cn=_as_optional_str(ssl_subject.get("CN")),
        ssl_cert_issuer_o=_as_optional_str(ssl_issuer.get("O")),
        ssl_cert_fingerprint=_extract_cert_fingerprint(ssl_cert),
        ssl_cert_serial=_extract_cert_serial(ssl_cert),
        ssl_cert_pubkey_bits=_as_optional_int(ssl_pubkey.get("bits")),
        ssl_cert_pubkey_type=_as_optional_str(ssl_pubkey.get("type")),
        ssl_cert_expired=_as_optional_bool(ssl_cert.get("expired")),
        ssl_versions=[str(value) for value in ssl_data.get("versions", []) or [] if value],
        ssl_cipher=_extract_ssl_cipher(ssl_data),
        ssl_jarm=_as_optional_str(ssl_data.get("jarm")),
        vulns=_extract_vuln_ids(raw_vulns),
        org=_as_optional_str(banner.get("org")),
        asn=_as_optional_str(banner.get("asn")),
        hostnames=[str(value) for value in banner.get("hostnames", []) or [] if value],
        domains=[str(value) for value in banner.get("domains", []) or [] if value],
        shodan_module=_as_optional_str(shodan_meta.get("module")),
    )


def generate_pivot_queries(meta: ShodanBannerMeta) -> List[str]:
    queries: List[str] = []

    if meta.html_hash not in (None, 0):
        queries.append(f"http.html_hash:{meta.html_hash}")
    if meta.banner_hash not in (None, 0):
        queries.append(f"hash:{meta.banner_hash}")
    if meta.headers_hash not in (None, 0):
        queries.append(f"http.headers_hash:{meta.headers_hash}")
    if meta.favicon_hash not in (None, 0):
        queries.append(f"http.favicon.hash:{meta.favicon_hash}")
    if meta.ssl_jarm and not set(meta.ssl_jarm) <= {"0"}:
        queries.append(f'ssl.jarm:"{meta.ssl_jarm}"')
    if meta.ssl_cert_fingerprint:
        queries.append(f'ssl.cert.fingerprint:"{meta.ssl_cert_fingerprint}"')

    if meta.http_title:
        for known_title in ("OpenClaw Control", "Clawdbot Control", "Moltbot Control"):
            if known_title.lower() in meta.http_title.lower():
                queries.append(f'http.title:"{known_title}" port:{meta.port}')
                break

    return queries


def detect_platform(os_value: Optional[str]) -> Optional[str]:
    if not os_value:
        return None

    lowered = os_value.lower()
    if "windows" in lowered:
        return "windows"
    if "mac" in lowered or "darwin" in lowered or "os x" in lowered:
        return "macos"
    if "linux" in lowered or "ubuntu" in lowered or "debian" in lowered:
        return "linux"
    return None


def cross_reference_vulns(
    shodan_vulns: Sequence[str],
    rules_vulns: Sequence[Dict[str, Any]],
) -> Dict[str, List[str]]:
    shodan_set = {str(value) for value in shodan_vulns if value}
    rules_set = {str(vuln["id"]) for vuln in rules_vulns if vuln.get("id")}
    return {
        "confirmed": sorted(shodan_set & rules_set),
        "shodan_only": sorted(shodan_set - rules_set),
        "scanner_only": sorted(rules_set - shodan_set),
    }


def _extract_favicon_hash(http: Dict[str, Any]) -> Optional[int]:
    favicon = http.get("favicon", {}) or {}
    values = []
    if isinstance(favicon, dict):
        values.extend(
            [
                favicon.get("hash"),
                favicon.get("mmh3"),
                favicon.get("murmurhash3"),
            ]
        )
    values.append(http.get("favicon_hash"))

    for value in values:
        parsed = _as_optional_int(value)
        if parsed is not None:
            return parsed
    return None


def _extract_cert_fingerprint(ssl_cert: Dict[str, Any]) -> Optional[str]:
    fingerprint = ssl_cert.get("fingerprint", {}) or {}
    return _as_optional_str(fingerprint.get("sha256"))


def _extract_cert_serial(ssl_cert: Dict[str, Any]) -> Optional[str]:
    serial = ssl_cert.get("serial")
    if serial in (None, ""):
        return None
    return str(serial)


def _extract_ssl_cipher(ssl_data: Dict[str, Any]) -> Optional[str]:
    cipher = ssl_data.get("cipher", {}) or {}
    if isinstance(cipher, dict):
        return _as_optional_str(cipher.get("name"))
    return _as_optional_str(cipher)


def _extract_vuln_ids(raw_vulns: Any) -> List[str]:
    if isinstance(raw_vulns, dict):
        return sorted(str(value) for value in raw_vulns.keys() if value)
    if isinstance(raw_vulns, list):
        return sorted(str(value) for value in raw_vulns if value)
    return []


def _as_optional_str(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    return str(value)


def _as_optional_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_optional_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    return bool(value)
