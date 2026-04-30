import argparse
import asyncio
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlparse

import httpx

from database import SessionLocal
from models import Monitor


REALISTIC_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

COMMON_ACCEPT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}

PROTECTION_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "akamai": "Akamai",
    "imperva": "Imperva",
    "sucuri": "Sucuri",
    "incapsula": "Incapsula",
    "f5 big-ip": "F5",
    "bot protection": "Bot Protection",
    "web application firewall": "WAF",
    "waf": "WAF",
    "ddos-guard": "DDoS-Guard",
    "fastly": "Fastly",
    "cloudfront": "CloudFront",
    "cdn77": "CDN77",
    "vpn gateway": "VPN Gateway",
}


@dataclass
class TruthResult:
    timestamp: str
    target_url: str
    status_code: Optional[int]
    is_real_up: bool
    error: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def normalize_target(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme:
        return url.strip().rstrip("/")
    return f"https://{url.strip().rstrip('/')}"


def load_targets_from_db(active_only: bool = True, user_id: Optional[int] = None) -> List[str]:
    db = SessionLocal()
    try:
        query = db.query(Monitor.target_url)
        if active_only:
            query = query.filter(Monitor.is_active.is_(True))
        if user_id is not None:
            query = query.filter(Monitor.user_id == user_id)

        targets = [row.target_url for row in query.distinct().all() if row.target_url]
        return sorted({normalize_target(target) for target in targets})
    finally:
        db.close()


def extract_registered_domain(target_url: str) -> str:
    host = (urlparse(target_url).hostname or "").lower()
    parts = [part for part in host.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def extract_hostname(target_url: str) -> str:
    return (urlparse(normalize_target(target_url)).hostname or "").lower()


def filter_targets_by_root_domain(targets: Sequence[str], root_site: str) -> List[str]:
    root_host = extract_hostname(root_site)
    if not root_host:
        return []

    if root_host.startswith("www."):
        base_host = root_host[4:]
    else:
        base_host = root_host

    allowed_hosts = {root_host, base_host}

    filtered = []
    for target in targets:
        host = extract_hostname(target)
        if not host:
            continue
        if host in allowed_hosts or host.endswith(f".{base_host}"):
            filtered.append(target)

    return sorted(set(filtered))


def filter_targets_by_registered_domain(targets: Sequence[str], site: str) -> List[str]:
    normalized_site = normalize_target(site)
    site_domain = extract_registered_domain(normalized_site)
    filtered = [
        target
        for target in targets
        if extract_registered_domain(target) == site_domain
    ]
    return sorted(set(filtered))


def detect_protection(response: httpx.Response) -> Optional[str]:
    haystacks = [
        response.headers.get("server", ""),
        response.headers.get("via", ""),
        response.headers.get("x-cdn", ""),
        response.headers.get("x-sucuri-id", ""),
        response.headers.get("x-iinfo", ""),
    ]
    haystacks.extend(
        f"{key}: {value}"
        for key, value in response.headers.items()
        if key.lower().startswith(("cf-", "x-", "server"))
    )

    try:
        haystacks.append(response.text[:800])
    except Exception:
        pass

    blob = " ".join(part.lower() for part in haystacks if part)
    for needle, label in PROTECTION_SIGNATURES.items():
        if needle in blob:
            return label

    if response.status_code in {401, 403, 405, 429, 503} and any(
        marker in blob
        for marker in (
            "challenge",
            "captcha",
            "checking your browser",
            "verify you are human",
            "security check",
            "blocked",
        )
    ):
        return "Protected Access"

    return None


def classify_ground_truth(response: httpx.Response) -> tuple[bool, str]:
    status_code = response.status_code
    protection = detect_protection(response)

    if protection:
        return True, f"protected:{protection}"
    if 200 <= status_code < 400:
        return True, ""
    if status_code in {401, 403, 405, 429, 503}:
        return False, f"http_{status_code}"
    if 400 <= status_code < 500:
        return False, f"http_{status_code}"
    if status_code >= 500:
        return False, f"http_{status_code}"
    return False, f"http_{status_code}"


def build_headers() -> dict:
    return {
        **COMMON_ACCEPT_HEADERS,
        "User-Agent": REALISTIC_USER_AGENTS[0],
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }


async def fetch_truth(client: httpx.AsyncClient, target_url: str) -> TruthResult:
    timestamp = utc_now_iso()
    headers = build_headers()

    try:
        response = await client.get(target_url, headers=headers)
        is_real_up, error = classify_ground_truth(response)
        return TruthResult(
            timestamp=timestamp,
            target_url=target_url,
            status_code=response.status_code,
            is_real_up=is_real_up,
            error=error,
        )
    except httpx.TimeoutException:
        return TruthResult(timestamp=timestamp, target_url=target_url, status_code=None, is_real_up=False, error="timeout")
    except httpx.ConnectError:
        return TruthResult(timestamp=timestamp, target_url=target_url, status_code=None, is_real_up=False, error="connect_error")
    except httpx.HTTPError as exc:
        return TruthResult(timestamp=timestamp, target_url=target_url, status_code=None, is_real_up=False, error=exc.__class__.__name__.lower())
    except Exception as exc:
        return TruthResult(timestamp=timestamp, target_url=target_url, status_code=None, is_real_up=False, error=exc.__class__.__name__.lower())


def ensure_output_header(path: Path, append: bool) -> None:
    if append and path.exists() and path.stat().st_size > 0:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["timestamp", "target_url", "status_code", "is_real_up", "error"])


def append_results(path: Path, results: Sequence[TruthResult]) -> None:
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        for result in results:
            writer.writerow(
                [
                    result.timestamp,
                    result.target_url,
                    "" if result.status_code is None else result.status_code,
                    result.is_real_up,
                    result.error,
                ]
            )


async def collect_cycles(
    targets: Sequence[str],
    output_path: Path,
    interval_seconds: float,
    cycles: int,
    timeout_seconds: float,
) -> None:
    timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 10.0))
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=True) as client:
        for cycle_index in range(cycles):
            results = await asyncio.gather(*(fetch_truth(client, target) for target in targets))
            append_results(output_path, results)

            up_count = sum(1 for item in results if item.is_real_up)
            down_count = len(results) - up_count
            print(
                f"[cycle {cycle_index + 1}/{cycles}] "
                f"wrote {len(results)} rows: up={up_count} down={down_count}"
            )

            if cycle_index < cycles - 1:
                await asyncio.sleep(interval_seconds)


def parse_targets(raw_targets: Optional[Iterable[str]]) -> List[str]:
    if not raw_targets:
        return []
    normalized = [normalize_target(item) for item in raw_targets if item and item.strip()]
    return sorted(set(normalized))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate ground-truth labels for currently monitored sites."
    )
    parser.add_argument(
        "--targets",
        nargs="*",
        help="Explicit target URLs to label. This is the safest mode and is recommended.",
    )
    parser.add_argument(
        "--user-id",
        type=int,
        default=None,
        help="Optional user filter when loading targets from the database.",
    )
    parser.add_argument(
        "--include-inactive",
        action="store_true",
        help="Include inactive monitors when loading targets from the database.",
    )
    parser.add_argument(
        "--from-db-site",
        default=None,
        help="Load targets from the database, but only for the same registered domain as this site.",
    )
    parser.add_argument(
        "--from-db-root",
        default=None,
        help="Load only the selected root host and its subdomains from the database.",
    )
    parser.add_argument(
        "--output",
        default="ground_truth.csv",
        help="CSV file to write.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=10.0,
        help="Delay between collection cycles.",
    )
    parser.add_argument(
        "--cycles",
        type=int,
        default=30,
        help="Number of collection cycles to run.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=15.0,
        help="Per-request timeout.",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to an existing CSV instead of replacing it.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    targets = parse_targets(args.targets)
    if not targets:
        if args.from_db_root:
            targets = filter_targets_by_root_domain(
                load_targets_from_db(
                    active_only=not args.include_inactive,
                    user_id=args.user_id,
                ),
                args.from_db_root,
            )
        elif args.from_db_site:
            targets = filter_targets_by_registered_domain(
                load_targets_from_db(
                    active_only=not args.include_inactive,
                    user_id=args.user_id,
                ),
                args.from_db_site,
            )
        else:
            raise SystemExit(
                "Refusing to load every active monitor from the database. "
                "Pass --targets https://example.com, "
                "--from-db-root https://example.com, "
                "or --from-db-site https://example.com."
            )

    if not targets:
        raise SystemExit("No targets found. Pass --targets or create active monitor records first.")

    output_path = Path(args.output)
    ensure_output_header(output_path, append=args.append)

    print(f"Collecting ground truth for {len(targets)} target(s)")
    for target in targets:
        print(f" - {target}")

    asyncio.run(
        collect_cycles(
            targets=targets,
            output_path=output_path,
            interval_seconds=args.interval_seconds,
            cycles=args.cycles,
            timeout_seconds=args.timeout_seconds,
        )
    )

    print(f"Ground truth written to {output_path}")


if __name__ == "__main__":
    main()
