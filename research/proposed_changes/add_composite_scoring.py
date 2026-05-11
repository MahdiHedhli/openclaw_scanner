"""
Proposed: Composite Multi-Layer Fingerprint Scoring Engine
==========================================================

Replaces the flat additive scoring in infer_product_confidence() with a
3-tier architecture:
  1. Per-layer confidence scoring (7 independent fingerprint layers)
  2. Context-aware weight adjustment (proxy, WAF, data source awareness)
  3. Dempster-Shafer-inspired evidence combination

This module is designed to be integrated into inference.py.

Research basis: Run 7 (2026-03-25) — Composite Multi-Layer Fingerprint Scoring
References:
  - Nmap service/OS detection scoring (GainedPoints/TotalPoints ratio)
  - Fingerprint.com Smart Signals / Suspect Score (weighted additive, rare = heavier)
  - Dempster-Shafer evidence theory (belief function fusion)
  - FL4IoT / IDENTIFY papers (multi-layer IoT device fingerprinting)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple
import math


# ---------------------------------------------------------------------------
# Tier 0: Fingerprint Layer Definitions
# ---------------------------------------------------------------------------

class FingerprintLayer(str, Enum):
    """The 7 independent fingerprint signal layers."""
    HTTP_CONTENT = "http_content"      # Titles, body markers, scripts, headers, JSON keys, errors
    TLS_CERT = "tls_cert"              # Certificate attributes, JARM hash, self-signed
    HTTP2 = "http2"                    # SETTINGS frame, ALPN negotiation
    TIMING = "timing"                  # TTFB ratios, timing anomalies
    WEBSOCKET = "websocket"            # WS upgrade responses, subprotocols
    MDNS = "mdns"                      # Service types, TXT records, instance names
    SHODAN_BANNER = "shodan_banner"    # Banner fields, hash pivots, CPE, vulns


# Default weights per layer (sum to ~1.0 for normalization reference)
# These should ultimately be calibrated from ground-truth data.
DEFAULT_LAYER_WEIGHTS: Dict[FingerprintLayer, float] = {
    FingerprintLayer.HTTP_CONTENT: 0.30,
    FingerprintLayer.TLS_CERT: 0.15,
    FingerprintLayer.HTTP2: 0.08,
    FingerprintLayer.TIMING: 0.05,
    FingerprintLayer.WEBSOCKET: 0.12,
    FingerprintLayer.MDNS: 0.20,
    FingerprintLayer.SHODAN_BANNER: 0.10,
}


# ---------------------------------------------------------------------------
# Tier 1: Per-Layer Confidence Result
# ---------------------------------------------------------------------------

@dataclass
class LayerConfidence:
    """Confidence result from a single fingerprint layer."""
    layer: FingerprintLayer
    confidence: float         # 0.0 to 1.0
    available: bool           # Was data available for this layer?
    conditions_matched: int   # How many conditions matched
    conditions_total: int     # How many conditions were testable
    signals: List[str] = field(default_factory=list)  # Human-readable signal descriptions

    @property
    def match_ratio(self) -> float:
        """Nmap-style GainedPoints/TotalPoints ratio."""
        if self.conditions_total == 0:
            return 0.0
        return self.conditions_matched / self.conditions_total


# ---------------------------------------------------------------------------
# Tier 2: Context Flags and Weight Adjustment
# ---------------------------------------------------------------------------

@dataclass
class ContextFlags:
    """Detected environmental context that affects signal reliability."""
    proxy_detected: bool = False
    proxy_type: Optional[str] = None       # "cloudflare", "nginx", "aws_alb", etc.
    waf_detected: bool = False
    waf_type: Optional[str] = None
    data_source: str = "active"            # "active", "shodan_only", "mixed"
    mdns_available: bool = False
    tls_probed: bool = False
    h2_probed: bool = False
    ws_probed: bool = False
    timing_probed: bool = False


# Weight adjustment multipliers based on context
PROXY_ADJUSTMENTS: Dict[FingerprintLayer, float] = {
    # When a reverse proxy is detected, TLS and H2 signals reflect the proxy,
    # not the origin. HTTP content and WebSocket signals pass through.
    FingerprintLayer.TLS_CERT: 0.2,        # Heavily reduced — cert is proxy's
    FingerprintLayer.HTTP2: 0.3,           # H2 SETTINGS are proxy's
    FingerprintLayer.TIMING: 0.5,          # Proxy adds latency but ratios partially survive
    FingerprintLayer.HTTP_CONTENT: 1.2,    # Content passes through — slightly boost
    FingerprintLayer.WEBSOCKET: 1.1,       # WS tunneled through — slight boost
    FingerprintLayer.MDNS: 1.0,            # Unaffected
    FingerprintLayer.SHODAN_BANNER: 0.7,   # Some banner fields reflect proxy
}

WAF_ADJUSTMENTS: Dict[FingerprintLayer, float] = {
    FingerprintLayer.TIMING: 0.3,          # WAF distorts timing significantly
    FingerprintLayer.HTTP_CONTENT: 0.8,    # WAF may inject/modify content
    FingerprintLayer.TLS_CERT: 0.3,        # WAF typically terminates TLS
    FingerprintLayer.HTTP2: 0.4,           # WAF may re-negotiate H2
    FingerprintLayer.WEBSOCKET: 0.9,       # WS usually tunneled
    FingerprintLayer.MDNS: 1.0,            # Unaffected
    FingerprintLayer.SHODAN_BANNER: 0.6,   # Banner reflects WAF
}


def adjust_weights(
    base_weights: Dict[FingerprintLayer, float],
    context: ContextFlags,
) -> Dict[FingerprintLayer, float]:
    """
    Adjust per-layer weights based on detected context.

    Returns a new weight dict with context-appropriate multipliers applied.
    Layers without available data get weight 0.
    """
    adjusted = dict(base_weights)

    # Apply proxy adjustments
    if context.proxy_detected:
        for layer, multiplier in PROXY_ADJUSTMENTS.items():
            adjusted[layer] = adjusted.get(layer, 0.0) * multiplier

    # Apply WAF adjustments (compounds with proxy if both present)
    if context.waf_detected:
        for layer, multiplier in WAF_ADJUSTMENTS.items():
            adjusted[layer] = adjusted.get(layer, 0.0) * multiplier

    # Zero out layers without data
    if not context.tls_probed:
        adjusted[FingerprintLayer.TLS_CERT] = 0.0
    if not context.h2_probed:
        adjusted[FingerprintLayer.HTTP2] = 0.0
    if not context.ws_probed:
        adjusted[FingerprintLayer.WEBSOCKET] = 0.0
    if not context.timing_probed:
        adjusted[FingerprintLayer.TIMING] = 0.0
    if not context.mdns_available:
        adjusted[FingerprintLayer.MDNS] = 0.0

    # Shodan-only mode: zero out active-probe layers
    if context.data_source == "shodan_only":
        for layer in [FingerprintLayer.HTTP_CONTENT, FingerprintLayer.TLS_CERT,
                       FingerprintLayer.HTTP2, FingerprintLayer.TIMING,
                       FingerprintLayer.WEBSOCKET]:
            adjusted[layer] = 0.0

    # Boost mDNS when available (it's the most authoritative source)
    if context.mdns_available:
        adjusted[FingerprintLayer.MDNS] = adjusted.get(FingerprintLayer.MDNS, 0.0) * 1.5

    return adjusted


# ---------------------------------------------------------------------------
# Tier 3: Evidence Combination (Dempster-Shafer Inspired)
# ---------------------------------------------------------------------------

@dataclass
class CompositeScore:
    """Final composite fingerprint score with full breakdown."""
    product_confidence: float              # Combined product identification confidence [0, 1]
    per_layer: Dict[FingerprintLayer, LayerConfidence]
    context: ContextFlags
    adjusted_weights: Dict[FingerprintLayer, float]
    contributing_layers: int               # Number of layers with data
    notes: List[str] = field(default_factory=list)


def combine_evidence(
    layer_results: Dict[FingerprintLayer, LayerConfidence],
    weights: Dict[FingerprintLayer, float],
    decay_factor: float = 0.5,
) -> Tuple[float, List[str]]:
    """
    Combine per-layer evidence using a simplified Dempster-Shafer-inspired
    formula.

    For each layer i with confidence c_i and weight w_i:
      belief_i = c_i * w_i (normalized)
      uncertainty_i = 1 - c_i

    Combined belief = 1 - prod(1 - belief_i) for all available layers
    Combined uncertainty = prod(uncertainty_i)
    Final = Combined belief * (1 - combined_uncertainty * decay_factor)

    The decay_factor controls how much residual uncertainty penalizes the
    final score. At 0.0, uncertainty is ignored. At 1.0, full penalty.
    0.5 is a reasonable default.

    Returns (final_confidence, notes).
    """
    notes: List[str] = []
    active_beliefs: List[float] = []
    active_uncertainties: List[float] = []

    # Normalize weights so the available layers sum to 1.0
    available_layers = {
        layer: w for layer, w in weights.items()
        if layer in layer_results and layer_results[layer].available and w > 0
    }

    if not available_layers:
        return 0.0, ["No fingerprint layers had data available."]

    weight_sum = sum(available_layers.values())
    if weight_sum == 0:
        return 0.0, ["All layer weights are zero after context adjustment."]

    for layer, raw_weight in available_layers.items():
        result = layer_results[layer]
        normalized_weight = raw_weight / weight_sum
        belief = result.confidence * normalized_weight
        uncertainty = 1.0 - result.confidence

        active_beliefs.append(belief)
        active_uncertainties.append(uncertainty)
        notes.append(
            f"  {layer.value}: conf={result.confidence:.3f} "
            f"weight={normalized_weight:.3f} "
            f"belief={belief:.3f} "
            f"matched={result.conditions_matched}/{result.conditions_total}"
        )

    # Dempster-Shafer-inspired combination
    # Combined belief: probability that at least one layer's evidence holds
    combined_belief = 1.0 - math.prod(1.0 - b for b in active_beliefs)

    # Combined uncertainty: product of per-layer uncertainties
    combined_uncertainty = math.prod(active_uncertainties)

    # Final score: belief discounted by residual uncertainty
    final = combined_belief * (1.0 - combined_uncertainty * decay_factor)

    # Clamp to [0, 1]
    final = max(0.0, min(1.0, final))

    notes.insert(0, f"Layers contributing: {len(available_layers)}")
    notes.append(f"Combined belief: {combined_belief:.4f}")
    notes.append(f"Combined uncertainty: {combined_uncertainty:.4f}")
    notes.append(f"Final confidence: {final:.4f}")

    return final, notes


def compute_composite_score(
    layer_results: Dict[FingerprintLayer, LayerConfidence],
    context: ContextFlags,
    base_weights: Optional[Dict[FingerprintLayer, float]] = None,
    decay_factor: float = 0.5,
) -> CompositeScore:
    """
    Top-level function: compute a composite fingerprint score from
    per-layer results and environmental context.

    This is intended to replace infer_product_confidence() in inference.py.
    """
    if base_weights is None:
        base_weights = dict(DEFAULT_LAYER_WEIGHTS)

    adjusted = adjust_weights(base_weights, context)
    final_confidence, notes = combine_evidence(layer_results, adjusted, decay_factor)

    contributing = sum(
        1 for layer, result in layer_results.items()
        if result.available and adjusted.get(layer, 0) > 0
    )

    return CompositeScore(
        product_confidence=final_confidence,
        per_layer=layer_results,
        context=context,
        adjusted_weights=adjusted,
        contributing_layers=contributing,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Version Confidence Voting Model
# ---------------------------------------------------------------------------

class VersionSignalType(str, Enum):
    """Types of version identification signals, ordered by reliability."""
    DIRECT_HINT = "direct_hint"          # Explicit version string in response
    MDNS_TXT = "mdns_txt"               # mDNS TXT record version= key
    ASSET_HASH = "asset_hash"           # JS/CSS bundle hash matches known version
    FAVICON_HASH = "favicon_hash"       # Favicon hash matches known version
    BEHAVIORAL = "behavioral"           # Endpoint pattern matches version range
    TIMING = "timing"                   # TTFB profile matches version


# Base confidence per signal type
VERSION_SIGNAL_BASE_CONFIDENCE: Dict[VersionSignalType, Tuple[float, float]] = {
    VersionSignalType.DIRECT_HINT: (0.95, 0.99),
    VersionSignalType.MDNS_TXT: (0.93, 0.98),
    VersionSignalType.ASSET_HASH: (0.85, 0.95),
    VersionSignalType.FAVICON_HASH: (0.70, 0.85),
    VersionSignalType.BEHAVIORAL: (0.50, 0.70),
    VersionSignalType.TIMING: (0.30, 0.50),
}


@dataclass
class VersionSignal:
    """A single version identification signal."""
    signal_type: VersionSignalType
    version: str
    confidence: float
    source: str


def vote_on_version(signals: List[VersionSignal]) -> List[VersionSignal]:
    """
    Apply a voting model to multiple version signals.

    If multiple independent signals agree on the same version, boost
    confidence. If they disagree, the highest-confidence single signal
    wins but overall confidence is capped.

    Returns a deduplicated, re-scored list of version candidates.
    """
    if not signals:
        return []

    # Group by version
    version_groups: Dict[str, List[VersionSignal]] = {}
    for sig in signals:
        version_groups.setdefault(sig.version, []).append(sig)

    results: List[VersionSignal] = []
    for version, group in version_groups.items():
        best = max(group, key=lambda s: s.confidence)
        agreement_count = len(group)

        if agreement_count >= 3:
            # Strong agreement: boost by up to 0.05
            boosted = min(0.99, best.confidence + 0.05)
        elif agreement_count == 2:
            # Moderate agreement: boost by up to 0.03
            boosted = min(0.99, best.confidence + 0.03)
        else:
            boosted = best.confidence

        # If there are competing versions, cap non-winning candidates
        results.append(VersionSignal(
            signal_type=best.signal_type,
            version=version,
            confidence=boosted,
            source=f"voted({agreement_count} signals, best={best.source})",
        ))

    # Sort by confidence descending
    results.sort(key=lambda s: s.confidence, reverse=True)

    # If top two candidates are close in confidence, cap both
    # (indicates ambiguity)
    if len(results) >= 2:
        gap = results[0].confidence - results[1].confidence
        if gap < 0.10:
            # Ambiguous — cap the winner
            results[0].confidence = min(results[0].confidence, 0.75)

    return results


# ---------------------------------------------------------------------------
# Integration sketch: how this replaces infer_product_confidence()
# ---------------------------------------------------------------------------

def infer_product_confidence_v2(
    observations: Dict[str, Any],  # ProbeObservation dict keyed by path
    rules: Dict[str, Any],
    context: Optional[ContextFlags] = None,
    verbose: bool = False,
) -> CompositeScore:
    """
    Drop-in replacement for infer_product_confidence() that returns a
    CompositeScore instead of a bare float.

    For backward compatibility, callers can use:
        score = infer_product_confidence_v2(...).product_confidence
    """
    if context is None:
        context = ContextFlags()

    # Step 1: Compute per-layer confidence
    # (Each function below would extract layer-specific signals from
    #  observations and rules, returning a LayerConfidence.)
    layer_results: Dict[FingerprintLayer, LayerConfidence] = {}

    # HTTP Content layer — always available if we have observations
    layer_results[FingerprintLayer.HTTP_CONTENT] = _compute_http_content_layer(
        observations, rules
    )

    # Other layers populated if their data is available
    if context.tls_probed:
        layer_results[FingerprintLayer.TLS_CERT] = _compute_tls_layer(observations, rules)
    if context.h2_probed:
        layer_results[FingerprintLayer.HTTP2] = _compute_h2_layer(observations, rules)
    if context.timing_probed:
        layer_results[FingerprintLayer.TIMING] = _compute_timing_layer(observations, rules)
    if context.ws_probed:
        layer_results[FingerprintLayer.WEBSOCKET] = _compute_ws_layer(observations, rules)
    if context.mdns_available:
        layer_results[FingerprintLayer.MDNS] = _compute_mdns_layer(observations, rules)

    # Shodan banner layer — available when banner metadata is present
    layer_results[FingerprintLayer.SHODAN_BANNER] = _compute_banner_layer(
        observations, rules
    )

    # Step 2 & 3: Adjust weights and combine
    return compute_composite_score(layer_results, context)


# ---------------------------------------------------------------------------
# Stub per-layer computation functions
# (To be implemented when integrating into inference.py)
# ---------------------------------------------------------------------------

def _compute_http_content_layer(observations, rules) -> LayerConfidence:
    """Compute HTTP content layer confidence.

    This is essentially the existing infer_product_confidence() logic,
    now scoped to HTTP content signals only.
    """
    # Placeholder — actual implementation would mirror existing logic
    return LayerConfidence(
        layer=FingerprintLayer.HTTP_CONTENT,
        confidence=0.0,
        available=True,
        conditions_matched=0,
        conditions_total=0,
    )


def _compute_tls_layer(observations, rules) -> LayerConfidence:
    """Compute TLS certificate/JARM layer confidence."""
    return LayerConfidence(
        layer=FingerprintLayer.TLS_CERT,
        confidence=0.0,
        available=True,
        conditions_matched=0,
        conditions_total=0,
    )


def _compute_h2_layer(observations, rules) -> LayerConfidence:
    """Compute HTTP/2 SETTINGS fingerprint layer confidence."""
    return LayerConfidence(
        layer=FingerprintLayer.HTTP2,
        confidence=0.0,
        available=True,
        conditions_matched=0,
        conditions_total=0,
    )


def _compute_timing_layer(observations, rules) -> LayerConfidence:
    """Compute timing-based fingerprint layer confidence."""
    return LayerConfidence(
        layer=FingerprintLayer.TIMING,
        confidence=0.0,
        available=True,
        conditions_matched=0,
        conditions_total=0,
    )


def _compute_ws_layer(observations, rules) -> LayerConfidence:
    """Compute WebSocket handshake fingerprint layer confidence."""
    return LayerConfidence(
        layer=FingerprintLayer.WEBSOCKET,
        confidence=0.0,
        available=True,
        conditions_matched=0,
        conditions_total=0,
    )


def _compute_mdns_layer(observations, rules) -> LayerConfidence:
    """Compute mDNS/DNS-SD fingerprint layer confidence."""
    return LayerConfidence(
        layer=FingerprintLayer.MDNS,
        confidence=0.0,
        available=True,
        conditions_matched=0,
        conditions_total=0,
    )


def _compute_banner_layer(observations, rules) -> LayerConfidence:
    """Compute Shodan banner metadata layer confidence."""
    return LayerConfidence(
        layer=FingerprintLayer.SHODAN_BANNER,
        confidence=0.0,
        available=False,  # Only available when Shodan data present
        conditions_matched=0,
        conditions_total=0,
    )
