"""
Proposed addition: Container/OCI Image Fingerprinting Module
============================================================

Research date: 2026-03-26
Cross-cutting topic: X3

This module adds container-level fingerprinting capabilities to the OpenClaw
scanner. It detects OpenClaw deployments running in Docker/OCI containers by:
1. Detecting exposed Docker Registry APIs and enumerating OpenClaw images
2. Detecting exposed Docker daemon APIs and inspecting running containers
3. Extracting container signals from HTTP responses (container ID hostnames)
4. Cross-referencing container metadata with HTTP fingerprint results

Gated behind an opt-in `--container` flag. No new required dependencies.
Uses only stdlib (urllib, json, hashlib, re) for HTTP requests.
"""

from dataclasses import dataclass, field
from typing import Optional
import hashlib
import json
import re


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass
class DockerRegistryInfo:
    """Metadata extracted from an exposed Docker Registry API."""
    host: str
    port: int = 5000
    api_version: str = ""          # e.g. "registry/2.0"
    repositories: list[str] = field(default_factory=list)
    openclaw_repos: list[str] = field(default_factory=list)
    openclaw_tags: list[str] = field(default_factory=list)
    openclaw_labels: dict[str, str] = field(default_factory=dict)
    openclaw_version_from_tag: Optional[str] = None


@dataclass
class DockerDaemonInfo:
    """Metadata extracted from an exposed Docker daemon API."""
    host: str
    port: int = 2375
    docker_version: str = ""
    api_version: str = ""
    os: str = ""
    arch: str = ""
    kernel_version: str = ""
    openclaw_containers: list[dict] = field(default_factory=list)


@dataclass
class ContainerSignals:
    """Container-level signals extracted from HTTP responses."""
    is_containerized: bool = False
    container_id: Optional[str] = None    # 12-char hex from hostname
    image_repo: Optional[str] = None
    image_tag: Optional[str] = None
    image_labels: dict[str, str] = field(default_factory=dict)
    layer_digests: list[str] = field(default_factory=list)
    registry_info: Optional[DockerRegistryInfo] = None
    daemon_info: Optional[DockerDaemonInfo] = None
    confidence_adjustment: float = 0.0    # additive adjustment to product confidence


@dataclass
class ContainerFingerprintResult:
    """Combined container fingerprinting result for a target."""
    host: str
    signals: ContainerSignals = field(default_factory=ContainerSignals)
    version_from_container: Optional[str] = None
    product_confirmed: bool = False
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Known OpenClaw container image identifiers
# ---------------------------------------------------------------------------

KNOWN_OPENCLAW_IMAGE_REPOS = [
    "openclaw/openclaw",
    "ghcr.io/openclaw/openclaw",
    "alpine/openclaw",
    "openeuler/openclaw",
    "coollabsio/openclaw",
]

KNOWN_OPENCLAW_IMAGE_PATTERNS = [
    re.compile(r"openclaw", re.IGNORECASE),
    re.compile(r"clawdbot", re.IGNORECASE),
    re.compile(r"moltbot", re.IGNORECASE),
]

# OCI labels that definitively identify OpenClaw
OPENCLAW_IDENTIFYING_LABELS = {
    "org.opencontainers.image.source": re.compile(
        r"github\.com/openclaw/openclaw", re.IGNORECASE
    ),
    "org.opencontainers.image.title": re.compile(
        r"openclaw|clawdbot|moltbot", re.IGNORECASE
    ),
    "org.opencontainers.image.vendor": re.compile(
        r"openclaw", re.IGNORECASE
    ),
}

# Known OpenClaw Docker default ports
DOCKER_REGISTRY_PORTS = [5000, 5001]
DOCKER_DAEMON_PORTS = [2375, 2376]

# Container ID pattern (12-char hex, typical Docker short container ID)
CONTAINER_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")

# CalVer version pattern from image tags
CALVER_TAG_PATTERN = re.compile(r"^v?(\d{4}\.\d+\.\d+(?:-\d+)?)$")


# ---------------------------------------------------------------------------
# Docker Registry API detection and enumeration
# ---------------------------------------------------------------------------

def detect_docker_registry(host: str, port: int = 5000,
                           timeout: float = 5.0) -> Optional[DockerRegistryInfo]:
    """
    Probe a host:port for an exposed Docker Registry API.

    Detection method:
    - GET /v2/ — the Docker Distribution spec requires this endpoint.
      If the response contains the 'Docker-Distribution-Api-Version' header,
      a registry is present (even on 401 responses).

    Returns DockerRegistryInfo if a registry is detected, None otherwise.

    NOTE: This is a sketch — actual HTTP requests use the scanner's
    existing _fetch() infrastructure with configurable timeouts and
    rate limiting.
    """
    info = DockerRegistryInfo(host=host, port=port)

    # Step 1: Check /v2/ for registry presence
    # Response header: Docker-Distribution-Api-Version: registry/2.0
    # Even 401 responses include this header
    # >>> resp = _fetch(f"http://{host}:{port}/v2/", timeout=timeout)
    # >>> if "Docker-Distribution-Api-Version" not in resp.headers:
    # >>>     return None
    # >>> info.api_version = resp.headers["Docker-Distribution-Api-Version"]

    # Step 2: Enumerate repositories (only works if unauthenticated)
    # GET /v2/_catalog
    # >>> resp = _fetch(f"http://{host}:{port}/v2/_catalog", timeout=timeout)
    # >>> if resp.status == 200:
    # >>>     info.repositories = resp.json().get("repositories", [])

    # Step 3: Check each repo for OpenClaw image patterns
    # >>> for repo in info.repositories:
    # >>>     for pattern in KNOWN_OPENCLAW_IMAGE_PATTERNS:
    # >>>         if pattern.search(repo):
    # >>>             info.openclaw_repos.append(repo)

    # Step 4: For OpenClaw repos, list tags
    # GET /v2/<repo>/tags/list
    # >>> for repo in info.openclaw_repos:
    # >>>     resp = _fetch(f"http://{host}:{port}/v2/{repo}/tags/list")
    # >>>     info.openclaw_tags = resp.json().get("tags", [])

    # Step 5: For the latest tag, fetch manifest and config to get labels
    # GET /v2/<repo>/manifests/<tag>
    # Accept: application/vnd.oci.image.manifest.v1+json
    # Then fetch config blob for labels

    # Step 6: Extract version from CalVer tags
    # >>> for tag in info.openclaw_tags:
    # >>>     m = CALVER_TAG_PATTERN.match(tag)
    # >>>     if m:
    # >>>         info.openclaw_version_from_tag = m.group(1)

    return info


def detect_docker_daemon(host: str, port: int = 2375,
                         timeout: float = 5.0) -> Optional[DockerDaemonInfo]:
    """
    Probe a host:port for an exposed Docker daemon API.

    Detection method:
    - GET /version — returns Docker daemon version info as JSON
    - GET /containers/json — lists running containers

    Returns DockerDaemonInfo if a daemon is detected, None otherwise.
    """
    info = DockerDaemonInfo(host=host, port=port)

    # Step 1: Check /version for Docker daemon
    # >>> resp = _fetch(f"http://{host}:{port}/version", timeout=timeout)
    # >>> if resp.status != 200:
    # >>>     return None
    # >>> data = resp.json()
    # >>> info.docker_version = data.get("Version", "")
    # >>> info.api_version = data.get("ApiVersion", "")
    # >>> info.os = data.get("Os", "")
    # >>> info.arch = data.get("Arch", "")
    # >>> info.kernel_version = data.get("KernelVersion", "")

    # Step 2: List running containers
    # GET /containers/json
    # >>> resp = _fetch(f"http://{host}:{port}/containers/json")
    # >>> containers = resp.json()

    # Step 3: Identify OpenClaw containers by image name
    # >>> for container in containers:
    # >>>     image = container.get("Image", "")
    # >>>     for pattern in KNOWN_OPENCLAW_IMAGE_PATTERNS:
    # >>>         if pattern.search(image):
    # >>>             info.openclaw_containers.append({
    # >>>                 "id": container.get("Id", "")[:12],
    # >>>                 "image": image,
    # >>>                 "state": container.get("State", ""),
    # >>>                 "ports": container.get("Ports", []),
    # >>>             })

    return info


# ---------------------------------------------------------------------------
# HTTP response container signal extraction
# ---------------------------------------------------------------------------

def extract_container_signals_from_http(
    probe_results: dict,  # path -> ProbeObservation
) -> ContainerSignals:
    """
    Extract container-related signals from existing HTTP probe results.

    Signals:
    1. Container ID hostname — Docker containers default to using the
       container ID (12-char hex) as hostname. This shows up in:
       - Server headers (some frameworks include hostname)
       - Error pages / stack traces
       - Health endpoint responses (e.g., {"hostname": "a1b2c3d4e5f6"})
       - X-Request-ID or similar headers containing hostname prefix

    2. Known container environment indicators:
       - NODE_ENV=production in error messages
       - /app or /home/node working directories in stack traces
       - Resource limits in health/status JSON (memory_limit, cpu_quota)
    """
    signals = ContainerSignals()

    for path, obs in probe_results.items():
        # Check for container ID in response body (health/status endpoints)
        if path in ("/health", "/api/health", "/api/status", "/status"):
            body = getattr(obs, "body", "") or ""

            # Look for hostname field with 12-char hex value
            hostname_match = re.search(
                r'"hostname"\s*:\s*"([0-9a-f]{12})"', body
            )
            if hostname_match:
                signals.is_containerized = True
                signals.container_id = hostname_match.group(1)

            # Look for container-typical resource fields
            if any(k in body for k in [
                "memory_limit", "cpu_quota", "container_id",
                "cgroup", "docker"
            ]):
                signals.is_containerized = True

        # Check headers for container signals
        headers = getattr(obs, "headers", {}) or {}

        # Some reverse proxies / frameworks include container hostname
        for header_name in ["x-served-by", "x-backend", "x-hostname"]:
            val = headers.get(header_name, "")
            if CONTAINER_ID_PATTERN.match(val):
                signals.is_containerized = True
                signals.container_id = val

    return signals


# ---------------------------------------------------------------------------
# Shodan banner container metadata extraction
# ---------------------------------------------------------------------------

def extract_container_metadata_from_shodan(banner: dict) -> ContainerSignals:
    """
    Extract container-related metadata from Shodan banner data.

    Shodan indexes Docker daemon and registry banners. When a target
    has both port 18789 (OpenClaw) and port 2375/5000 banners, the
    container metadata can be cross-referenced.

    Relevant Shodan fields:
    - product: "Docker" (on port 2375)
    - docker.version, docker.containers (on Docker API banners)
    - http.headers_hash (on port 5000 for registry detection)
    """
    signals = ContainerSignals()

    product = banner.get("product", "")
    port = banner.get("port", 0)

    # Docker daemon API banner
    if product == "Docker" and port in DOCKER_DAEMON_PORTS:
        signals.is_containerized = True
        # Extract Docker version from banner
        docker_data = banner.get("docker", {})
        if docker_data:
            pass  # Would populate daemon_info

    # Docker Registry banner
    if port in DOCKER_REGISTRY_PORTS:
        headers = banner.get("http", {}).get("headers", {})
        if "Docker-Distribution-Api-Version" in str(headers):
            signals.registry_info = DockerRegistryInfo(
                host=banner.get("ip_str", ""),
                port=port,
                api_version=headers.get(
                    "Docker-Distribution-Api-Version", ""
                ),
            )

    return signals


# ---------------------------------------------------------------------------
# Layer digest database (to be populated from lab captures)
# ---------------------------------------------------------------------------

# Placeholder: Map of known application layer digests -> OpenClaw version
# These would be populated by pulling official images and recording their
# layer digests:
#   skopeo inspect --raw docker://ghcr.io/openclaw/openclaw:<version>
#   crane manifest ghcr.io/openclaw/openclaw:<version>
KNOWN_LAYER_DIGESTS: dict[str, str] = {
    # "sha256:abcdef1234...": "2026.3.7",
    # "sha256:fedcba4321...": "2026.2.26",
}


def match_layer_digest(digest: str) -> Optional[str]:
    """Look up a layer digest in the known-versions database."""
    return KNOWN_LAYER_DIGESTS.get(digest)


# ---------------------------------------------------------------------------
# New condition types for the rules engine
# ---------------------------------------------------------------------------

NEW_CONDITION_TYPES = {
    "container_image_label": {
        "description": "Match an OCI image label key-value pair",
        "example": {
            "type": "container_image_label",
            "key": "org.opencontainers.image.source",
            "value_contains": "openclaw/openclaw",
        },
    },
    "container_image_repo": {
        "description": "Match container image repository name pattern",
        "example": {
            "type": "container_image_repo",
            "value_contains": "openclaw",
        },
    },
    "container_image_tag": {
        "description": "Match container image tag (version)",
        "example": {
            "type": "container_image_tag",
            "value_regex": r"^v?2026\.\d+\.\d+",
        },
    },
    "container_layer_digest": {
        "description": "Match a known application layer SHA256 digest",
        "example": {
            "type": "container_layer_digest",
            "value": "sha256:abcdef1234567890...",
        },
    },
    "docker_registry_exposed": {
        "description": "Boolean: Docker Registry API detected on the host",
        "example": {
            "type": "docker_registry_exposed",
            "value": True,
        },
    },
    "container_hostname_pattern": {
        "description": "Match hostname pattern typical of containerized deployments",
        "example": {
            "type": "container_hostname_pattern",
            "pattern": "docker_short_id",  # 12-char hex
        },
    },
}


# ---------------------------------------------------------------------------
# Example fingerprint rules using container signals
# ---------------------------------------------------------------------------

EXAMPLE_CONTAINER_RULES = [
    {
        "id": "openclaw-docker-registry-image",
        "family": "openclaw_container_confirmed",
        "label": "OpenClaw confirmed via Docker Registry image inspection",
        "confidence": 0.98,
        "notes": "Docker Registry API exposed on host contains an image "
                 "with OCI labels pointing to openclaw/openclaw source repo.",
        "all": [
            {
                "type": "docker_registry_exposed",
                "value": True,
            },
            {
                "type": "container_image_label",
                "key": "org.opencontainers.image.source",
                "value_contains": "openclaw/openclaw",
            },
        ],
    },
    {
        "id": "openclaw-docker-daemon-running",
        "family": "openclaw_container_confirmed",
        "label": "OpenClaw confirmed via Docker daemon container inspection",
        "confidence": 0.97,
        "notes": "Docker daemon API exposed on host has a running container "
                 "with an OpenClaw image.",
        "all": [
            {
                "type": "container_image_repo",
                "value_contains": "openclaw",
            },
        ],
    },
    {
        "id": "openclaw-containerized-hostname",
        "family": "openclaw_containerized_hint",
        "label": "OpenClaw likely running in Docker container (hostname signal)",
        "confidence": 0.15,
        "notes": "HTTP response from OpenClaw port contains a 12-char hex "
                 "hostname typical of Docker containers. Supplementary signal "
                 "only — does not identify the product, only the deployment mode.",
        "all": [
            {
                "type": "container_hostname_pattern",
                "pattern": "docker_short_id",
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Proposed CLI flags
# ---------------------------------------------------------------------------

PROPOSED_CLI_FLAGS = {
    "--container": {
        "help": "Enable container fingerprinting (probe Docker Registry "
                "and daemon APIs on target hosts)",
        "action": "store_true",
        "default": False,
    },
    "--registry-port": {
        "help": "Docker Registry API port to probe (default: 5000)",
        "type": int,
        "default": 5000,
    },
    "--daemon-port": {
        "help": "Docker daemon API port to probe (default: 2375)",
        "type": int,
        "default": 2375,
    },
}


# ---------------------------------------------------------------------------
# Integration sketch for probe.py
# ---------------------------------------------------------------------------

def container_fingerprint_workflow(host: str, opts: dict) -> ContainerFingerprintResult:
    """
    Full container fingerprinting workflow for a single target.

    Called from the main scan loop when --container flag is set.

    Steps:
    1. Extract container signals from existing HTTP probe results
    2. If --container enabled, probe Docker Registry API
    3. If --container enabled, probe Docker daemon API
    4. Cross-reference all container signals
    5. Return combined result with version and confidence adjustment
    """
    result = ContainerFingerprintResult(host=host)

    # Step 1: Extract signals from HTTP probes (always, no extra requests)
    # signals = extract_container_signals_from_http(probe_results)
    # result.signals = signals

    # Step 2: Probe Docker Registry (opt-in)
    if opts.get("container"):
        registry_port = opts.get("registry_port", 5000)
        registry = detect_docker_registry(host, port=registry_port)
        if registry and registry.openclaw_repos:
            result.signals.registry_info = registry
            result.product_confirmed = True
            result.notes.append(
                f"OpenClaw image found in exposed Docker Registry: "
                f"{registry.openclaw_repos}"
            )
            if registry.openclaw_version_from_tag:
                result.version_from_container = registry.openclaw_version_from_tag
                result.notes.append(
                    f"Version from image tag: {registry.openclaw_version_from_tag}"
                )

    # Step 3: Probe Docker daemon (opt-in)
    if opts.get("container"):
        daemon_port = opts.get("daemon_port", 2375)
        daemon = detect_docker_daemon(host, port=daemon_port)
        if daemon and daemon.openclaw_containers:
            result.signals.daemon_info = daemon
            result.product_confirmed = True
            result.notes.append(
                f"OpenClaw container running: "
                f"{daemon.openclaw_containers}"
            )

    # Step 4: Calculate confidence adjustment
    if result.product_confirmed:
        result.signals.confidence_adjustment = 0.15  # Strong boost
    elif result.signals.is_containerized:
        result.signals.confidence_adjustment = 0.02  # Mild hint

    return result
