import statistics
from typing import Dict, Iterable, Optional

from .models import HoneypotAssessment, ProbeObservation

KNOWN_HONEYPOT_SIGNATURES = {
    "cowrie": ("cowrie", "kippo"),
    "glastopf": ("glastopf",),
    "dionaea": ("dionaea",),
    "conpot": ("conpot",),
    "heralding": ("heralding",),
    "honeyd": ("honeyd",),
    "tpot": ("t-pot", "tpot"),
}


def assess_honeypot(
    observations: Dict[str, ProbeObservation],
    metadata: Optional[dict] = None,
    threshold: float = 0.7,
) -> HoneypotAssessment:
    metadata = metadata or {}
    signals = []
    probability = 0.0
    known_signature = _detect_known_signature(observations)
    if known_signature:
        probability = max(probability, 0.92)
        signals.append(f"matched known honeypot signature: {known_signature}")

    honeyscore = _coerce_float(metadata.get("shodan_honeyscore"))
    if honeyscore is not None:
        probability = max(probability, min(max(honeyscore, 0.0), 1.0))
        signals.append(f"Shodan honeyscore={honeyscore:.2f}")

    timing_cv, uniform_timing = _assess_timing_uniformity(observations.values())
    if uniform_timing and _has_uniform_responses(observations.values()):
        probability = max(probability, 0.35)
        signals.append(
            "suspiciously uniform response timing across many near-identical responses"
        )

    notes = None
    if signals:
        notes = (
            "Conservative honeypot assessment. Strong signatures dominate; "
            "timing-only evidence is treated as weak to avoid false positives."
        )

    return HoneypotAssessment(
        probable=probability >= threshold,
        probability=round(probability, 2),
        timing_cv=round(timing_cv, 4) if timing_cv is not None else None,
        uniform_timing=uniform_timing,
        known_signature=known_signature,
        signals=signals,
        notes=notes,
    )


def _detect_known_signature(observations: Dict[str, ProbeObservation]) -> Optional[str]:
    values = []
    for observation in observations.values():
        if observation.title:
            values.append(observation.title)
        if observation.error_text:
            values.append(observation.error_text)
        values.extend(observation.body_markers)
        values.extend(observation.headers.values())

    corpus = " ".join(values).lower()
    for signature, markers in KNOWN_HONEYPOT_SIGNATURES.items():
        if any(marker in corpus for marker in markers):
            return signature
    return None


def _assess_timing_uniformity(
    observations: Iterable[ProbeObservation],
) -> tuple[Optional[float], bool]:
    timings = [
        observation.response_time_ms
        for observation in observations
        if observation.status is not None and observation.response_time_ms not in (None, 0)
    ]
    if len(timings) < 5:
        return None, False

    mean_timing = statistics.mean(timings)
    if mean_timing <= 0:
        return None, False

    stdev = statistics.stdev(timings)
    cv = stdev / mean_timing
    return cv, cv < 0.02


def _has_uniform_responses(observations: Iterable[ProbeObservation]) -> bool:
    successful = [observation for observation in observations if observation.status is not None]
    if len(successful) < 6:
        return False

    titles = {
        observation.title.strip().lower()
        for observation in successful
        if observation.title
    }
    body_hashes = {
        observation.body_sha256.lower()
        for observation in successful
        if observation.body_sha256
    }
    return len(titles) <= 1 and len(body_hashes) <= 1


def _coerce_float(value) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
