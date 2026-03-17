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
    status: Optional[int] = None
    final_url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None
    body_length: int = 0
    body_sha256: Optional[str] = None
    title: Optional[str] = None
    js_files: List[str] = field(default_factory=list)
    json_keys: List[str] = field(default_factory=list)
    body_markers: List[str] = field(default_factory=list)
    version_hints: List[str] = field(default_factory=list)
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
class VulnerabilityMatch:
    id: str
    title: str
    affected: bool
    confidence: float
    reasoning: str
    fixed_in: Optional[str] = None
    severity: Optional[str] = None
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
    fingerprint_matches: List[FingerprintMatch] = field(default_factory=list)
    matched_versions: List[VersionMatch] = field(default_factory=list)
    vulnerability_matches: List[VulnerabilityMatch] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_target": self.input_target,
            "source": self.source,
            "probed_base": self.probed_base,
            "metadata": self.metadata,
            "product_confidence": self.product_confidence,
            "observations": {
                path: observation.to_dict()
                for path, observation in self.observations.items()
            },
            "fingerprint_matches": [
                match.to_dict() for match in self.fingerprint_matches
            ],
            "matched_versions": [match.to_dict() for match in self.matched_versions],
            "vulnerability_matches": [
                match.to_dict() for match in self.vulnerability_matches
            ],
            "errors": list(self.errors),
        }
