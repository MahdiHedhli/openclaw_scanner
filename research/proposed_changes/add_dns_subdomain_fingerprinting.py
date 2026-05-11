"""
Proposed addition: DNS and subdomain fingerprinting for OpenClaw identification.

Research date: 2026-03-27
Topic: Cross-cutting X5

This module provides DNS-layer fingerprinting signals:
1. Reverse DNS hostname pattern matching
2. Shodan banner DNS field extraction and analysis
3. Subdomain naming convention matching
4. Passive DNS enrichment integration (optional, API-dependent)

Dependencies:
- stdlib only for core functionality (socket, re)
- Optional: Shodan API for subdomain enumeration and reverse DNS

Integration: Adds new condition types to the rules engine and enriches
scan results with DNS-derived confidence signals.
"""

import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DnsFingerprint:
    """DNS-derived fingerprinting signals for a scan target."""
    ip: str
    hostnames: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ptr_record: Optional[str] = None
    ptr_exists: bool = False
    hostname_matches_product: bool = False
    matched_patterns: List[str] = field(default_factory=list)
    subdomain_count: int = 0
    related_subdomains: List[str] = field(default_factory=list)
    deployment_type: Optional[str] = None  # "self-hosted", "cloud", "vps", "unknown"
    first_seen: Optional[str] = None  # from pDNS, if available
    confidence_contribution: float = 0.0


@dataclass
class SubdomainEnumerationResult:
    """Results from subdomain enumeration for a parent domain."""
    domain: str
    subdomains: List[str] = field(default_factory=list)
    openclaw_related: List[str] = field(default_factory=list)
    source: str = "shodan"  # "shodan", "crtsh", "pdns"
    timestamp: Optional[str] = None


# ---------------------------------------------------------------------------
# OpenClaw hostname/subdomain patterns
# ---------------------------------------------------------------------------

# Direct product name patterns (high confidence)
PRODUCT_NAME_PATTERNS = [
    re.compile(r"(?i)\bopenclaw\b"),
    re.compile(r"(?i)\bclawdbot\b"),
    re.compile(r"(?i)\bmoltbot\b"),
]

# Gateway role patterns (medium confidence — need corroborating signals)
GATEWAY_ROLE_PATTERNS = [
    re.compile(r"(?i)\bclaw-gw\b"),
    re.compile(r"(?i)\bopenclaw-gw\b"),
    re.compile(r"(?i)\bmoltbot-gw\b"),
    re.compile(r"(?i)\bclawdbot-gw\b"),
    re.compile(r"(?i)\bai-gateway\b"),
    re.compile(r"(?i)\bagent-gw\b"),
]

# Generic AI/agent patterns (low confidence — common false positives)
GENERIC_AI_PATTERNS = [
    re.compile(r"(?i)\bai-agent\b"),
    re.compile(r"(?i)\bassistant\b"),
    re.compile(r"(?i)\bchatbot\b"),
]

# Cloud provider PTR patterns (used for deployment type detection)
CLOUD_PTR_PATTERNS = {
    "aws": re.compile(r"(?i)ec2.*amazonaws\.com$"),
    "gcp": re.compile(r"(?i)\.googleusercontent\.com$"),
    "azure": re.compile(r"(?i)\.cloudapp\.azure\.com$"),
    "digitalocean": re.compile(r"(?i)\.digitalocean\.com$"),
    "linode": re.compile(r"(?i)\.linode\.com$"),
    "vultr": re.compile(r"(?i)\.vultr\.com$"),
    "hetzner": re.compile(r"(?i)\.hetzner\.com$"),
    "ovh": re.compile(r"(?i)\.ovh\.(net|com)$"),
    "oracle": re.compile(r"(?i)\.oraclecloud\.com$"),
    "hostinger": re.compile(r"(?i)\.hostinger\b"),
}

# Known mDNS/local hostname patterns from Topic #9
LOCAL_HOSTNAME_PATTERNS = [
    re.compile(r"(?i)^openclaw-gw-[a-f0-9]+\.local$"),
    re.compile(r"(?i)^moltbot-[a-z0-9]+\.local$"),
    re.compile(r"(?i)^clawdbot-[a-z0-9]+\.local$"),
]


# ---------------------------------------------------------------------------
# Core fingerprinting functions
# ---------------------------------------------------------------------------

def fingerprint_dns(
    ip: str,
    shodan_banner: Optional[Dict[str, Any]] = None,
    resolve_ptr: bool = True,
    timeout: float = 5.0,
) -> DnsFingerprint:
    """
    Build a DNS fingerprint for a target IP address.

    Combines Shodan banner DNS data with active reverse DNS lookups
    to produce hostname-based identification signals.

    Args:
        ip: Target IP address.
        shodan_banner: Optional Shodan banner dict containing 'hostnames', 'domains' fields.
        resolve_ptr: If True, perform active reverse DNS lookup.
        timeout: DNS resolution timeout.

    Returns:
        DnsFingerprint with extracted signals.
    """
    fp = DnsFingerprint(ip=ip)

    # Extract from Shodan banner
    if shodan_banner:
        fp.hostnames = [str(h).lower() for h in shodan_banner.get("hostnames", []) if h]
        fp.domains = [str(d).lower() for d in shodan_banner.get("domains", []) if d]

    # Active reverse DNS lookup
    if resolve_ptr:
        ptr = _reverse_dns_lookup(ip, timeout)
        if ptr:
            fp.ptr_record = ptr.lower()
            fp.ptr_exists = True
            if ptr.lower() not in fp.hostnames:
                fp.hostnames.append(ptr.lower())

    # Match hostnames against product patterns
    all_hostnames = " ".join(fp.hostnames)

    for pattern in PRODUCT_NAME_PATTERNS:
        if pattern.search(all_hostnames):
            fp.hostname_matches_product = True
            fp.matched_patterns.append(f"product_name:{pattern.pattern}")
            fp.confidence_contribution = max(fp.confidence_contribution, 0.35)

    for pattern in GATEWAY_ROLE_PATTERNS:
        if pattern.search(all_hostnames):
            fp.hostname_matches_product = True
            fp.matched_patterns.append(f"gateway_role:{pattern.pattern}")
            fp.confidence_contribution = max(fp.confidence_contribution, 0.20)

    for pattern in GENERIC_AI_PATTERNS:
        if pattern.search(all_hostnames):
            fp.matched_patterns.append(f"generic_ai:{pattern.pattern}")
            fp.confidence_contribution = max(fp.confidence_contribution, 0.05)

    # Detect deployment type from PTR/hostname patterns
    fp.deployment_type = _detect_deployment_type(fp.hostnames, fp.ptr_record)

    return fp


def extract_dns_from_shodan_banner(banner: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract all DNS-relevant fields from a Shodan banner record.

    This extends the Shodan banner extraction (Topic #8) with
    DNS-specific fields that are currently unused by the scanner.

    Returns dict with:
        hostnames: List[str] - reverse DNS hostnames
        domains: List[str] - parent domains
        hostname_matches: List[str] - OpenClaw pattern matches
        deployment_type: str - detected deployment type
    """
    hostnames = [str(h).lower() for h in banner.get("hostnames", []) if h]
    domains = [str(d).lower() for d in banner.get("domains", []) if d]

    matches = []
    for hostname in hostnames:
        for pattern in PRODUCT_NAME_PATTERNS + GATEWAY_ROLE_PATTERNS:
            if pattern.search(hostname):
                matches.append(hostname)
                break

    deployment_type = _detect_deployment_type(hostnames, None)

    return {
        "hostnames": hostnames,
        "domains": domains,
        "hostname_matches": matches,
        "deployment_type": deployment_type,
    }


def enumerate_related_subdomains(
    domain: str,
    shodan_api_key: Optional[str] = None,
) -> SubdomainEnumerationResult:
    """
    Enumerate subdomains for a parent domain to find related OpenClaw services.

    Uses Shodan's /dns/domain/{domain} API endpoint.

    Args:
        domain: Parent domain to enumerate (e.g., "example.com").
        shodan_api_key: Shodan API key for subdomain queries.

    Returns:
        SubdomainEnumerationResult with discovered subdomains.
    """
    result = SubdomainEnumerationResult(
        domain=domain,
        source="shodan",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    if not shodan_api_key:
        return result

    url = f"https://api.shodan.io/dns/domain/{domain}?key={shodan_api_key}"
    try:
        from urllib.request import urlopen, Request
        import json

        req = Request(url, headers={"User-Agent": "OpenClawScanner/DNS-Enum"})
        with urlopen(req, timeout=15) as response:
            data = json.loads(response.read())

        subdomains = data.get("subdomains", [])
        result.subdomains = [f"{sub}.{domain}" for sub in subdomains]

        # Filter for OpenClaw-related subdomains
        for fqdn in result.subdomains:
            for pattern in PRODUCT_NAME_PATTERNS + GATEWAY_ROLE_PATTERNS:
                if pattern.search(fqdn):
                    result.openclaw_related.append(fqdn)
                    break

    except Exception:
        pass  # Fail silently — subdomain enum is best-effort enrichment

    return result


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _reverse_dns_lookup(ip: str, timeout: float = 5.0) -> Optional[str]:
    """Perform a reverse DNS (PTR) lookup for an IP address."""
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(original_timeout)


def _detect_deployment_type(
    hostnames: List[str],
    ptr_record: Optional[str],
) -> str:
    """
    Detect deployment type from hostname patterns.

    Returns: "cloud-{provider}", "self-hosted", or "unknown"
    """
    all_names = " ".join(hostnames)
    if ptr_record:
        all_names += " " + ptr_record

    for provider, pattern in CLOUD_PTR_PATTERNS.items():
        if pattern.search(all_names):
            return f"cloud-{provider}"

    # If PTR exists but doesn't match known cloud providers,
    # likely self-hosted or a smaller VPS provider
    if any(hostnames) or ptr_record:
        return "self-hosted"

    return "unknown"


# ---------------------------------------------------------------------------
# New condition types for the rules engine
# ---------------------------------------------------------------------------

NEW_CONDITION_TYPES = """
New condition types to add to inference.py _condition_matches():

1. hostname_pattern — Regex match against reverse DNS hostnames
   {
     "type": "hostname_pattern",
     "value": "(?i)(openclaw|clawdbot|moltbot)"
   }
   Implementation: Match regex against all hostnames from DnsFingerprint.

2. hostname_contains — Substring match against reverse DNS hostnames
   {
     "type": "hostname_contains",
     "value": "openclaw"
   }
   Implementation: Case-insensitive substring search across hostnames.

3. domain_contains — Substring match against parent domains
   {
     "type": "domain_contains",
     "value": "example.com"
   }
   Implementation: Case-insensitive substring search across domains.

4. ptr_exists — Boolean check for PTR record existence
   {
     "type": "ptr_exists",
     "value": true
   }
   Implementation: Check DnsFingerprint.ptr_exists.

5. deployment_type — Match detected deployment type
   {
     "type": "deployment_type",
     "value": "cloud-aws"
   }
   Implementation: String match against DnsFingerprint.deployment_type.

6. subdomain_count_gte — Minimum count of OpenClaw-related subdomains
   {
     "type": "subdomain_count_gte",
     "value": 3
   }
   Implementation: Check SubdomainEnumerationResult.openclaw_related length.
"""


# ---------------------------------------------------------------------------
# Example fingerprint rules
# ---------------------------------------------------------------------------

EXAMPLE_RULES = [
    {
        "id": "dns-product-hostname",
        "family": "openclaw_dns_hostname",
        "label": "Reverse DNS hostname contains OpenClaw product name",
        "confidence": 0.75,
        "notes": "Hostname directly references openclaw/clawdbot/moltbot. Strong independent signal.",
        "all": [
            {
                "type": "hostname_pattern",
                "value": "(?i)(openclaw|clawdbot|moltbot)"
            }
        ]
    },
    {
        "id": "dns-gateway-hostname-with-http",
        "family": "openclaw_dns_gateway_corroborated",
        "label": "Gateway hostname pattern corroborated by HTTP 200 on root",
        "confidence": 0.60,
        "notes": "Gateway-role hostname pattern + responding HTTP service. Medium confidence.",
        "all": [
            {
                "type": "hostname_pattern",
                "value": "(?i)(claw-gw|openclaw-gw|moltbot-gw|clawdbot-gw)"
            },
            {
                "type": "path_status",
                "path": "/",
                "statuses": [200]
            }
        ]
    },
    {
        "id": "dns-cloud-default-ptr",
        "family": "openclaw_cloud_deployment",
        "label": "Cloud provider PTR with OpenClaw UI title",
        "confidence": 0.90,
        "notes": "Generic cloud PTR but confirmed OpenClaw via page title. Cloud deployment detected.",
        "all": [
            {
                "type": "deployment_type",
                "value": "cloud-aws"
            },
            {
                "type": "title_contains",
                "path": "/",
                "value": "OpenClaw Control"
            }
        ]
    },
    {
        "id": "dns-no-ptr-self-signed",
        "family": "openclaw_unconfigured",
        "label": "No PTR record suggests unconfigured/default deployment",
        "confidence": 0.10,
        "notes": "Absence of PTR is a weak negative signal. Combined with self-signed cert, suggests default deployment. Very low confidence alone.",
        "all": [
            {
                "type": "ptr_exists",
                "value": False
            }
        ]
    },
]


# ---------------------------------------------------------------------------
# CLI integration sketch
# ---------------------------------------------------------------------------

PROPOSED_CLI_FLAGS = """
Proposed CLI flags for DNS enrichment:

  --dns-enrich            Perform reverse DNS lookups and hostname pattern matching
                          for all scan targets. Adds DNS fingerprint signals to results.

  --dns-subdomains        Enumerate subdomains for discovered parent domains via Shodan API.
                          Finds related OpenClaw services on the same domain.

  --dns-timeout SECONDS   Timeout for DNS resolution (default: 5.0).

Example workflow:
  # Scan with DNS enrichment
  openclaw-scanner --targets hosts.txt --probe --dns-enrich

  # Discover related subdomains after initial scan
  openclaw-scanner --targets hosts.txt --probe --dns-enrich --dns-subdomains
"""


# ---------------------------------------------------------------------------
# Integration with composite scoring (Topic X1)
# ---------------------------------------------------------------------------

DNS_SCORING_NOTES = """
DNS fingerprinting integrates with the composite scoring engine (Topic X1)
as a new FingerprintLayer:

  FingerprintLayer.DNS (weight: 0.15)

Context-aware weight adjustments:
  - If proxy detected (Topic #11): DNS weight stays the same
    (DNS signals are NOT affected by reverse proxies)
  - If cloud PTR detected: DNS hostname confidence is reduced
    (generic cloud hostnames are not product-specific)
  - If Shodan data source: DNS enrichment is free (already in banner)
    → increase DNS weight slightly

The DNS layer provides an INDEPENDENT signal that survives HTTP-level
obfuscation, reverse proxy termination, and WAF blocking. It should
always be evaluated when available.
"""
