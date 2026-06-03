from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScanTarget:
    label: str
    source: str
    candidates: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_record: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeObservation:
    path: str
    url: str
    method: str = "GET"
    probe_name: Optional[str] = None
    status: Optional[int] = None
    final_url: Optional[str] = None
    response_time_ms: Optional[float] = None
    headers: Dict[str, str] = field(default_factory=dict)
    header_order: List[str] = field(default_factory=list)
    content_type: Optional[str] = None
    body_length: int = 0
    body_sha256: Optional[str] = None
    title: Optional[str] = None
    js_files: List[str] = field(default_factory=list)
    json_keys: List[str] = field(default_factory=list)
    body_markers: List[str] = field(default_factory=list)
    version_hints: List[str] = field(default_factory=list)
    cdp: Dict[str, str] = field(default_factory=dict)
    error_text: Optional[str] = None
    has_stack_trace: bool = False
    favicon_hash: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VersionMatch:
    version: str
    confidence: float
    source: str
    notes: Optional[str] = None
    exact: bool = False
    correlate: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FingerprintMatch:
    family: str
    confidence: float
    source: str
    label: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProxyDetection:
    detected: bool = False
    proxy_type: Optional[str] = None
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HoneypotAssessment:
    probable: bool = False
    probability: float = 0.0
    timing_cv: Optional[float] = None
    uniform_timing: bool = False
    known_signature: Optional[str] = None
    signals: List[str] = field(default_factory=list)
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerabilityMatch:
    id: str
    title: str
    affected: bool
    confidence: float
    reasoning: str
    fixed_in: Optional[str] = None
    severity: Optional[str] = None
    platform: Optional[str] = None
    surface: List[str] = field(default_factory=list)
    requires_auth: Optional[bool] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    input_target: str
    source: str
    probed_base: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    product_confidence: float = 0.0
    observations: Dict[str, ProbeObservation] = field(default_factory=dict)
    proxy_detection: Optional[ProxyDetection] = None
    honeypot_assessment: Optional[HoneypotAssessment] = None
    fingerprint_matches: List[FingerprintMatch] = field(default_factory=list)
    matched_versions: List[VersionMatch] = field(default_factory=list)
    vulnerability_matches: List[VulnerabilityMatch] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def status_distribution(self) -> Dict[int, int]:
        counts = Counter(
            observation.status
            for observation in self.observations.values()
            if observation.status is not None
        )
        return {status: counts[status] for status in sorted(counts)}

    def status_distribution_signature(self) -> str:
        return ";".join(
            f"{status}:{count}"
            for status, count in self.status_distribution().items()
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_target": self.input_target,
            "source": self.source,
            "probed_base": self.probed_base,
            "metadata": self.metadata,
            "product_confidence": self.product_confidence,
            "status_distribution": self.status_distribution(),
            "status_distribution_signature": self.status_distribution_signature(),
            "observations": {
                path: observation.to_dict()
                for path, observation in self.observations.items()
            },
            "proxy_detection": (
                self.proxy_detection.to_dict() if self.proxy_detection else None
            ),
            "honeypot_assessment": (
                self.honeypot_assessment.to_dict()
                if self.honeypot_assessment
                else None
            ),
            "fingerprint_matches": [
                match.to_dict() for match in self.fingerprint_matches
            ],
            "matched_versions": [match.to_dict() for match in self.matched_versions],
            "vulnerability_matches": [
                match.to_dict() for match in self.vulnerability_matches
            ],
            "errors": list(self.errors),
        }
