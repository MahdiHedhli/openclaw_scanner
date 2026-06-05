import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def load_calibration_candidates(path: str, output_format: str) -> str:
    rows = _load_rows(Path(path))
    candidates = select_calibration_candidates(rows)
    return render_calibration_candidates(candidates, output_format)


def select_calibration_candidates(
    rows: Iterable[Dict[str, Any]],
    min_confidence: float = 0.3,
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        confidence = _float_value(row.get("product_confidence"))
        family_count = _count_value(
            row.get("family_match_count")
            if row.get("family_match_count") not in (None, "")
            else row.get("family_matches")
            if row.get("family_matches") not in (None, "")
            else row.get("fingerprint_matches")
        )
        exact_count = _count_value(
            row.get("exact_version_count")
            if row.get("exact_version_count") not in (None, "")
            else row.get("exact_versions")
            if row.get("exact_versions") not in (None, "")
            else row.get("matched_versions")
        )
        signature = str(row.get("status_distribution_signature") or "").strip()

        if not _bool_value(row.get("has_signal")):
            continue
        if family_count != 0:
            continue
        if confidence < min_confidence:
            continue
        if exact_count != 0 or str(row.get("top_version") or "").strip():
            continue
        if not _is_interesting_signature(signature):
            continue

        candidate = {
            "anon_id": _anon_id(row, index),
            "confidence": round(confidence, 2),
            "status_distribution_signature": signature,
            "observed_paths_summary": _observed_paths_summary(row),
            "reason_tags": _reason_tags(confidence, signature),
        }
        candidates.append(candidate)

    return sorted(
        candidates,
        key=lambda item: (
            -float(item["confidence"]),
            item["status_distribution_signature"],
            item["anon_id"],
        ),
    )


def render_calibration_candidates(
    candidates: Iterable[Dict[str, Any]],
    output_format: str,
) -> str:
    rows = list(candidates)
    if output_format == "json":
        return json.dumps(rows, indent=2, sort_keys=True)
    if output_format == "ndjson":
        return "\n".join(json.dumps(row, sort_keys=True) for row in rows)
    if output_format == "csv":
        output = io.StringIO()
        fieldnames = [
            "anon_id",
            "confidence",
            "status_distribution_signature",
            "observed_paths_summary",
            "reason_tags",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    **row,
                    "reason_tags": ";".join(row.get("reason_tags", [])),
                }
            )
        return output.getvalue()

    lines = []
    for row in rows:
        lines.append(
            f"{row['anon_id']}: confidence={row['confidence']:.2f} "
            f"status={row['status_distribution_signature']} "
            f"reasons={';'.join(row.get('reason_tags', [])) or 'none'}"
        )
        if row.get("observed_paths_summary"):
            lines.append(f"  observed: {row['observed_paths_summary']}")
    return "\n".join(lines) + ("\n" if lines else "")


def _load_rows(path: Path) -> List[Dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        return _load_csv_rows(path.read_text(encoding="utf-8"))

    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return []
    if raw.lstrip().startswith("["):
        data = json.loads(raw)
        return [row for row in data if isinstance(row, dict)]
    if _looks_like_csv(raw):
        return _load_csv_rows(raw)
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _load_csv_rows(raw: str) -> List[Dict[str, Any]]:
    return [dict(row) for row in csv.DictReader(io.StringIO(raw))]


def _looks_like_csv(raw: str) -> bool:
    first_line = raw.splitlines()[0] if raw.splitlines() else ""
    return "," in first_line and "{" not in first_line and "[" not in first_line


def _anon_id(row: Dict[str, Any], index: int) -> str:
    for key in ("anon_id", "id", "active_rank"):
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return f"anon-{index:04d}"


def _observed_paths_summary(row: Dict[str, Any]) -> str:
    observed_paths = str(row.get("observed_paths") or "").strip()
    if observed_paths:
        parts = [part.strip() for part in observed_paths.split(";") if part.strip()]
        return "; ".join(parts[:8])

    details = []
    if row.get("observation_count") not in (None, ""):
        details.append(f"observation_count={row['observation_count']}")
    if row.get("error_count") not in (None, ""):
        details.append(f"error_count={row['error_count']}")
    return "; ".join(details)


def _reason_tags(confidence: float, signature: str) -> List[str]:
    tags = ["has_signal", "no_family_match", "no_exact_version"]
    if confidence >= 0.3:
        tags.append("product_confidence_ge_0_3")
    if signature == "200:35;400:2;404:1":
        tags.append("signature_200_35_400_2_404_1")
    if "401:" in signature:
        tags.append("auth_challenge_variant")
    if "400:" in signature and "404:" in signature:
        tags.append("api_shape_status_cluster")
    if "101:" in signature:
        tags.append("websocket_upgrade_cluster")
    return tags


def _is_interesting_signature(signature: str) -> bool:
    counts = _parse_status_signature(signature)
    if not counts:
        return False
    if signature == "200:35;400:2;404:1":
        return True
    if counts.get(200, 0) >= 25 and counts.get(400, 0) > 0 and counts.get(404, 0) > 0:
        return True
    if counts.get(401, 0) > 0 and counts.get(200, 0) >= 20:
        return True
    if counts.get(101, 0) > 0 and counts.get(200, 0) >= 10:
        return True
    return False


def _parse_status_signature(signature: str) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    for part in signature.split(";"):
        if ":" not in part:
            continue
        status, _, count = part.partition(":")
        try:
            counts[int(status)] = int(count)
        except ValueError:
            continue
    return counts


def _count_value(value: Any) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, list):
        return len(value)
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return 0
    if text.isdigit():
        return int(text)
    if text.startswith("["):
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError:
            return 1
        return len(loaded) if isinstance(loaded, list) else 1
    return len([part for part in text.split(";") if part.strip()])


def _float_value(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}
