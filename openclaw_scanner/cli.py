import argparse
import csv
import json
import io
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, List, Optional

from .inference import (
    correlate_vulnerabilities,
    infer_fingerprint_matches,
    infer_product_confidence,
    infer_versions,
    load_rules,
)
from .models import ProbeObservation, ScanResult
from .probe import DEFAULT_PROBE_PATHS, has_signal, probe_candidate
from .shodan_api import ShodanAPIError, resolve_shodan_api_key, search_shodan
from .sources import load_targets

VERSION_RE = re.compile(r"(?<![0-9A-Za-z])(20\d{2}\.\d+\.\d+(?:-[A-Za-z0-9]+)?)(?=$|[^0-9A-Za-z])")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fingerprint OpenClaw versions from direct targets, Shodan exports, or live Shodan API searches."
    )
    parser.add_argument("--target", action="append", default=[], help="Target base URL or host.")
    parser.add_argument("--targets-file", help="Path to a newline-delimited target list.")
    parser.add_argument("--shodan-file", help="Path to a Shodan export JSON or JSONL file.")
    parser.add_argument(
        "--shodan-query",
        action="append",
        default=[],
        help="Live Shodan search query. Can be repeated.",
    )
    parser.add_argument(
        "--shodan-key",
        help="Shodan API key. Falls back to SHODAN_API_KEY or .env if omitted.",
    )
    parser.add_argument(
        "--shodan-pages",
        type=int,
        default=1,
        help="Number of Shodan search result pages to fetch per query.",
    )
    parser.add_argument(
        "--shodan-fields",
        help="Comma-separated Shodan fields to request.",
    )
    parser.add_argument(
        "--shodan-minify",
        action="store_true",
        help="Use Shodan's minified search response mode.",
    )
    parser.add_argument(
        "--shodan-timeout",
        type=float,
        default=10.0,
        help="Timeout in seconds for live Shodan API requests.",
    )
    parser.add_argument(
        "--probe-path",
        action="append",
        default=[],
        help="Additional path to probe. Can be repeated.",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds.")
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of concurrent target workers.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=131072,
        help="Maximum number of response bytes to read per request.",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS certificates. Default behavior is permissive for scanning.",
    )
    parser.add_argument(
        "--rules-file",
        help="Path to a custom rules file. Defaults to openclaw_scanner/data/openclaw_rules.json.",
    )
    parser.add_argument(
        "--rescan-shodan",
        action="store_true",
        help="Actively probe hosts loaded from --shodan-file instead of relying on the exported banner data only.",
    )
    parser.add_argument(
        "--format",
        choices=("pretty", "json", "ndjson", "csv"),
        default="pretty",
        help="Output format.",
    )
    parser.add_argument("--output", help="Write output to this file instead of stdout.")
    parser.add_argument(
        "--user-agent",
        default="openclaw-scanner/0.1",
        help="User-Agent header to send.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    shodan_records = []
    if args.shodan_query:
        api_key = resolve_shodan_api_key(args.shodan_key)
        if not api_key:
            parser.error(
                "Provide --shodan-key, set SHODAN_API_KEY, or add SHODAN_API_KEY=... to .env for --shodan-query."
            )

        for query in args.shodan_query:
            try:
                response = search_shodan(
                    query=query,
                    api_key=api_key,
                    pages=max(args.shodan_pages, 1),
                    fields=args.shodan_fields,
                    minify=args.shodan_minify,
                    timeout=args.shodan_timeout,
                    user_agent=args.user_agent,
                )
            except ShodanAPIError as exc:
                parser.exit(2, f"Shodan API error: {exc}\n")
            shodan_records.extend(response["matches"])

    targets = load_targets(
        direct_targets=args.target,
        targets_file=args.targets_file,
        shodan_file=args.shodan_file,
        shodan_records=shodan_records,
    )

    if not targets:
        parser.error(
            "Provide at least one --target, --targets-file, --shodan-file, or --shodan-query."
        )

    rules = load_rules(args.rules_file)
    probe_paths = list(dict.fromkeys(DEFAULT_PROBE_PATHS + list(args.probe_path)))

    results = scan_targets(
        targets=targets,
        rules=rules,
        probe_paths=probe_paths,
        timeout=args.timeout,
        workers=max(args.workers, 1),
        max_bytes=max(args.max_bytes, 1024),
        verify_tls=args.verify_tls,
        user_agent=args.user_agent,
        rescan_shodan=args.rescan_shodan,
    )

    rendered = render_results(results, args.format)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")

    return 0


def scan_targets(
    targets,
    rules,
    probe_paths: Iterable[str],
    timeout: float,
    workers: int,
    max_bytes: int,
    verify_tls: bool,
    user_agent: str,
    rescan_shodan: bool,
):
    results: List[ScanResult] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(
                _scan_single_target,
                target,
                rules,
                probe_paths,
                timeout,
                max_bytes,
                verify_tls,
                user_agent,
                rescan_shodan,
            ): target
            for target in targets
        }

        for future in as_completed(future_map):
            results.append(future.result())

    return sorted(results, key=lambda item: item.input_target)


def _scan_single_target(
    target,
    rules,
    probe_paths: Iterable[str],
    timeout: float,
    max_bytes: int,
    verify_tls: bool,
    user_agent: str,
    rescan_shodan: bool,
) -> ScanResult:
    offline_observations = _observations_from_shodan_record(target.raw_record)
    if offline_observations and not rescan_shodan:
        result = ScanResult(
            input_target=target.label,
            source=target.source,
            probed_base=None,
            metadata=target.metadata,
            observations=offline_observations,
        )
        result.product_confidence = infer_product_confidence(offline_observations, rules)
        result.fingerprint_matches = infer_fingerprint_matches(
            offline_observations, rules
        )
        result.matched_versions = infer_versions(offline_observations, rules)
        result.vulnerability_matches = correlate_vulnerabilities(
            result.matched_versions, rules
        )
        return result

    last_result = ScanResult(
        input_target=target.label,
        source=target.source,
        probed_base=None,
        metadata=target.metadata,
    )

    for candidate in target.candidates:
        observations, errors = probe_candidate(
            base_url=candidate,
            paths=probe_paths,
            timeout=timeout,
            verify_tls=verify_tls,
            user_agent=user_agent,
            max_bytes=max_bytes,
        )
        prefixed_errors = _prefix_candidate_errors(candidate, errors)
        last_result.errors.extend(prefixed_errors)

        result = ScanResult(
            input_target=target.label,
            source=target.source,
            probed_base=candidate,
            metadata=target.metadata,
            observations=observations,
            errors=list(last_result.errors),
        )
        result.product_confidence = infer_product_confidence(observations, rules)
        result.fingerprint_matches = infer_fingerprint_matches(observations, rules)
        result.matched_versions = infer_versions(observations, rules)
        result.vulnerability_matches = correlate_vulnerabilities(
            result.matched_versions, rules
        )

        last_result = result
        if has_signal(observations):
            return result

    return last_result


def _observations_from_shodan_record(raw_record) -> dict:
    if not raw_record:
        return {}

    http_data = raw_record.get("http") or {}
    body_text = _build_shodan_text(raw_record)
    title = http_data.get("title") or raw_record.get("title")
    headers = _normalize_shodan_headers(http_data.get("headers") or {})
    server = http_data.get("server")
    if server and "server" not in headers:
        headers["server"] = server
    if body_text and "content-type" not in headers:
        headers["content-type"] = "text/plain"

    observation = ProbeObservation(
        path="/__shodan__",
        url=f"shodan://{raw_record.get('ip_str', 'unknown')}:{raw_record.get('port', 'unknown')}",
        status=raw_record.get("http", {}).get("status") or (200 if body_text or title else None),
        headers=headers,
        content_type=headers.get("content-type"),
        body_length=len(body_text.encode("utf-8", errors="ignore")),
        body_sha256=None,
        title=title,
        js_files=_extract_shodan_scripts(body_text),
        json_keys=[],
        body_markers=_extract_shodan_markers(body_text),
        version_hints=_extract_shodan_versions(body_text, headers),
        error=None,
    )
    return {observation.path: observation}


def _normalize_shodan_headers(headers) -> dict:
    if isinstance(headers, dict):
        return {str(key).lower(): str(value) for key, value in headers.items()}
    return {}


def _extract_shodan_scripts(html: str) -> List[str]:
    if not html:
        return []
    matches = []
    for chunk in html.split("<script"):
        if 'src="' in chunk:
            matches.append(chunk.split('src="', 1)[1].split('"', 1)[0])
        elif "src='" in chunk:
            matches.append(chunk.split("src='", 1)[1].split("'", 1)[0])
    return sorted(set(value for value in matches if value.endswith(".js")))


def _extract_shodan_markers(html: str) -> List[str]:
    haystack = html.lower()
    markers = []
    for marker in ("openclaw", "claw gateway", "clawdbot", "moltbot", "gateway token"):
        if marker in haystack:
            markers.append(marker)
    return sorted(set(markers))


def _extract_shodan_versions(html: str, headers: dict) -> List[str]:
    versions = set()
    haystacks = [html] + [str(value) for value in headers.values()]
    for haystack in haystacks:
        versions.update(VERSION_RE.findall(haystack))
    return sorted(versions)


def _build_shodan_text(raw_record) -> str:
    parts = []
    for key in ("product", "data"):
        value = raw_record.get(key)
        if isinstance(value, str) and value:
            parts.append(value)

    http_data = raw_record.get("http") or {}
    for key in ("title", "html"):
        value = http_data.get(key)
        if isinstance(value, str) and value:
            parts.append(value)

    mdns = raw_record.get("mdns") or {}
    services = mdns.get("services") or {}
    for service_name, service in services.items():
        parts.append(str(service_name))
        for key in ("name", "ptr"):
            value = service.get(key)
            if isinstance(value, str) and value:
                parts.append(value)
        for entry in service.get("data", []):
            parts.append(str(entry))

    answers = mdns.get("answers") or {}
    for records in answers.values():
        if isinstance(records, list):
            parts.extend(str(value) for value in records)

    return "\n".join(parts)


def render_results(results: List[ScanResult], output_format: str) -> str:
    serializable = [result.to_dict() for result in results]
    if output_format == "json":
        return json.dumps(serializable, indent=2, sort_keys=True)
    if output_format == "ndjson":
        return "\n".join(json.dumps(item, sort_keys=True) for item in serializable)
    if output_format == "csv":
        return _render_csv(results)
    return _render_pretty(results)


def _render_pretty(results: List[ScanResult]) -> str:
    blocks = []
    for result in results:
        lines = [
            f"Target: {result.input_target}",
            f"Source: {result.source}",
            f"Probed base: {result.probed_base or 'none'}",
            f"OpenClaw confidence: {result.product_confidence:.2f}",
        ]
        if result.metadata.get("shodan_query"):
            lines.append(f"Shodan query: {result.metadata['shodan_query']}")

        if result.fingerprint_matches:
            best_family = result.fingerprint_matches[0]
            family_label = best_family.label or best_family.family
            lines.append(
                "Top fingerprint family: "
                f"{family_label} (confidence {best_family.confidence:.2f}, source {best_family.source})"
            )
        else:
            lines.append("Top fingerprint family: none")

        if result.matched_versions:
            best = result.matched_versions[0]
            lines.append(
                f"Top version match: {best.version} (confidence {best.confidence:.2f}, source {best.source})"
            )
        else:
            lines.append("Top version match: none")

        if result.vulnerability_matches:
            lines.append("Vulnerability candidates:")
            for vuln in result.vulnerability_matches[:6]:
                surface = ",".join(vuln.surface) if vuln.surface else "unspecified"
                auth = (
                    "auth required"
                    if vuln.requires_auth is True
                    else "auth not required"
                    if vuln.requires_auth is False
                    else "auth unknown"
                )
                lines.append(
                    f"  - {vuln.id} [{vuln.severity or 'UNKNOWN'}] fixed in {vuln.fixed_in or 'unknown'}"
                )
                lines.append(f"    {vuln.title}")
                lines.append(f"    {auth}; surface={surface}")
        else:
            lines.append("Vulnerability candidates: none")

        observed_paths = []
        for path, observation in result.observations.items():
            status = observation.status if observation.status is not None else "ERR"
            marker_text = ",".join(observation.body_markers) if observation.body_markers else "-"
            observed_paths.append(f"{path}={status} markers={marker_text}")
        lines.append("Observed paths: " + "; ".join(observed_paths))

        if result.errors:
            lines.append("Errors: " + " | ".join(result.errors[:4]))

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks) + "\n"


def _render_csv(results: List[ScanResult]) -> str:
    output = io.StringIO()
    fieldnames = [
        "input_target",
        "source",
        "probed_base",
        "product_confidence",
        "shodan_query",
        "top_fingerprint_family",
        "top_fingerprint_confidence",
        "top_fingerprint_source",
        "fingerprint_families",
        "top_version",
        "top_version_confidence",
        "top_version_source",
        "matched_versions",
        "version_sources",
        "top_vulnerability",
        "top_vulnerability_severity",
        "vulnerability_ids",
        "vulnerability_count",
        "observed_paths",
        "markers",
        "error_count",
        "errors",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for result in results:
        top_fingerprint = (
            result.fingerprint_matches[0] if result.fingerprint_matches else None
        )
        top_version = result.matched_versions[0] if result.matched_versions else None
        top_vulnerability = (
            result.vulnerability_matches[0] if result.vulnerability_matches else None
        )
        writer.writerow(
            {
                "input_target": result.input_target,
                "source": result.source,
                "probed_base": result.probed_base or "",
                "product_confidence": f"{result.product_confidence:.2f}",
                "shodan_query": result.metadata.get("shodan_query", ""),
                "top_fingerprint_family": (
                    top_fingerprint.family if top_fingerprint else ""
                ),
                "top_fingerprint_confidence": (
                    f"{top_fingerprint.confidence:.2f}" if top_fingerprint else ""
                ),
                "top_fingerprint_source": (
                    top_fingerprint.source if top_fingerprint else ""
                ),
                "fingerprint_families": ";".join(
                    match.family for match in result.fingerprint_matches
                ),
                "top_version": top_version.version if top_version else "",
                "top_version_confidence": (
                    f"{top_version.confidence:.2f}" if top_version else ""
                ),
                "top_version_source": top_version.source if top_version else "",
                "matched_versions": ";".join(
                    match.version for match in result.matched_versions
                ),
                "version_sources": ";".join(
                    match.source for match in result.matched_versions
                ),
                "top_vulnerability": top_vulnerability.id if top_vulnerability else "",
                "top_vulnerability_severity": (
                    top_vulnerability.severity if top_vulnerability else ""
                ),
                "vulnerability_ids": ";".join(
                    vuln.id for vuln in result.vulnerability_matches
                ),
                "vulnerability_count": len(result.vulnerability_matches),
                "observed_paths": ";".join(
                    f"{path}={obs.status if obs.status is not None else 'ERR'}"
                    for path, obs in result.observations.items()
                ),
                "markers": ";".join(
                    sorted(
                        {
                            marker
                            for observation in result.observations.values()
                            for marker in observation.body_markers
                        }
                    )
                ),
                "error_count": len(result.errors),
                "errors": " | ".join(result.errors),
            }
        )

    return output.getvalue()


def _prefix_candidate_errors(base_url: str, errors: List[str]) -> List[str]:
    return [f"{base_url} {error}" for error in errors]
