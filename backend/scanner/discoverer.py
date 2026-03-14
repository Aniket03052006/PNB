"""Module 1 — Asset Discovery: DNS enumeration, CT logs, port scanning, API crawl.

Phase 6 rewrite: single if/else at entry point — demo mode returns 21 static
hostnames from demo_data; live mode does real DNS + CT + port scan.
"""

from __future__ import annotations

import logging
import socket
import asyncio
from typing import Any

import httpx

from backend.models import DiscoveredAsset, AssetType

logger = logging.getLogger("qarmor.discoverer")

# ── Constants ────────────────────────────────────────────────────────────────

COMMON_SUBDOMAINS = [
    "www", "api", "mail", "vpn", "remote", "gateway", "portal",
    "secure", "login", "auth", "admin", "app", "mobile", "mobileapi",
    "banking", "netbanking", "ibanking", "ib", "corporate", "corp",
    "pay", "payment", "payments", "upi", "neft", "rtgs", "imps",
    "cdn", "static", "assets", "media", "docs", "developer",
    "staging", "stage", "dev", "test", "uat", "sandbox",
    "smtp", "imap", "pop", "exchange", "mx",
    "ftp", "sftp", "swift", "cards", "loans", "fx", "trade",
    "custody", "sme", "kyc", "cms", "reporting", "legacy",
]

SCAN_PORTS = [443, 8443, 4433, 1194]

WELL_KNOWN_PATHS = [
    "/.well-known/openapi",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v1/api-docs",
    "/v2/api-docs",
]

# ── Helpers ──────────────────────────────────────────────────────────────────


def classify_asset_type(hostname: str, port: int) -> AssetType:
    """Infer asset type from hostname and port."""
    h = hostname.lower()
    if port in (1194, 500, 4500) or "vpn" in h or "remote" in h:
        return AssetType.VPN
    if "api" in h or "gateway" in h or "developer" in h or "swagger" in h:
        return AssetType.API
    if "mail" in h or "smtp" in h or "exchange" in h or "mx" in h:
        return AssetType.MAIL
    return AssetType.WEB


async def _resolve(hostname: str) -> str | None:
    """Resolve hostname to first IPv4/IPv6 address."""
    loop = asyncio.get_running_loop()
    try:
        results = await loop.run_in_executor(
            None, socket.getaddrinfo, hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM,
        )
        for _family, _type, _proto, _canon, sockaddr in results:
            return sockaddr[0]
    except socket.gaierror:
        pass
    return None


# ── DNS Subdomain Enumeration ────────────────────────────────────────────────


async def enumerate_subdomains_dns(domain: str) -> list[str]:
    """Brute-force subdomain discovery using DNS A/AAAA resolution."""
    found: list[str] = []
    loop = asyncio.get_running_loop()

    async def check(sub: str) -> None:
        fqdn = f"{sub}.{domain}"
        try:
            await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            found.append(fqdn)
        except socket.gaierror:
            pass

    # Run all checks concurrently (bounded by asyncio default)
    await asyncio.gather(*[check(s) for s in COMMON_SUBDOMAINS], return_exceptions=True)
    return sorted(set(found))


# ── Certificate Transparency Logs ────────────────────────────────────────────


async def query_ct_logs(domain: str) -> list[str]:
    """Query Certificate Transparency logs via crt.sh."""
    subdomains: set[str] = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        clean = line.strip().lstrip("*.")
                        if clean.endswith(domain) and " " not in clean:
                            subdomains.add(clean)
    except Exception as exc:
        logger.debug("CT log query failed: %s", exc)
    return sorted(subdomains)


# ── Port Scanning ────────────────────────────────────────────────────────────


async def scan_ports(host: str, ports: list[int] | None = None) -> list[int]:
    """Scan common TLS ports on a host."""
    ports = ports or SCAN_PORTS
    open_ports: list[int] = []
    loop = asyncio.get_running_loop()

    def _connect(target_host: str, target_port: int) -> bool:
        try:
            sock = socket.create_connection((target_host, target_port), timeout=2.0)
            sock.close()
            return True
        except Exception:
            return False

    async def probe(port: int) -> None:
        try:
            is_open = await loop.run_in_executor(None, _connect, host, port)
            if is_open:
                open_ports.append(port)
        except Exception:
            pass

    await asyncio.gather(*[probe(p) for p in ports], return_exceptions=True)
    return sorted(open_ports)


# ── API Endpoint Crawl ───────────────────────────────────────────────────────


async def crawl_api_endpoints(hostname: str, port: int = 443) -> list[str]:
    """Check well-known paths to detect swagger / OpenAPI endpoints."""
    found: list[str] = []
    scheme = "https" if port in (443, 8443) else "http"
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            for path in WELL_KNOWN_PATHS:
                url = f"{scheme}://{hostname}:{port}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code < 400:
                        found.append(path)
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("API crawl failed for %s:%d — %s", hostname, port, exc)
    return found


# ── Demo Mode ────────────────────────────────────────────────────────────────


def _demo_assets() -> list[DiscoveredAsset]:
    """Return the 21 demo assets from Phase 6 demo_data, zero network calls."""
    from backend.demo_data import DEMO_TRIMODE_FINGERPRINTS

    return [
        DiscoveredAsset(
            hostname=fp.hostname,
            ip=fp.ip,
            port=fp.port,
            asset_type=fp.asset_type,
            discovery_method="demo",
        )
        for fp in DEMO_TRIMODE_FINGERPRINTS
    ]


# ── Main Entry Point ────────────────────────────────────────────────────────


async def discover_assets(
    domain: str,
    *,
    demo: bool = False,
    include_ct: bool = True,
    include_port_scan: bool = True,
    include_api_crawl: bool = False,
) -> list[DiscoveredAsset]:
    """Full discovery pipeline.

    Single if/else at the top: demo mode returns static data;
    live mode performs DNS + CT + port scan + optional API crawl.
    """
    # ── Demo mode: instant return ────────────────────────────────────────
    if demo:
        logger.info("[DEMO] Returning 21 pre-built assets — no network calls")
        return _demo_assets()

    # ── Live mode ────────────────────────────────────────────────────────
    all_hosts: set[str] = {domain}

    # Step 1: DNS subdomain enumeration
    logger.info("DNS enumeration for %s …", domain)
    dns_results = await enumerate_subdomains_dns(domain)
    all_hosts.update(dns_results)
    logger.info("DNS found %d subdomains", len(dns_results))

    # Step 2: CT log query
    if include_ct:
        logger.info("CT log query for %s …", domain)
        ct_results = await query_ct_logs(domain)
        all_hosts.update(ct_results)
        logger.info("CT logs found %d subdomains", len(ct_results))

    # Step 3: Resolve + port scan
    assets: list[DiscoveredAsset] = []
    for host in sorted(all_hosts):
        ip = await _resolve(host)
        if ip is None:
            continue

        if include_port_scan:
            open_ports = await scan_ports(ip, SCAN_PORTS)
            for port in open_ports:
                atype = classify_asset_type(host, port)
                assets.append(DiscoveredAsset(
                    hostname=host, ip=ip, port=port,
                    asset_type=atype, discovery_method="dns+ct+portscan",
                ))

                # Optional API crawl for web/API assets
                if include_api_crawl and atype in (AssetType.WEB, AssetType.API):
                    api_paths = await crawl_api_endpoints(host, port)
                    if api_paths:
                        logger.info("API endpoints on %s:%d — %s", host, port, api_paths)
        else:
            # Default: assume 443
            assets.append(DiscoveredAsset(
                hostname=host, ip=ip, port=443,
                asset_type=classify_asset_type(host, 443),
                discovery_method="dns+ct",
            ))

    logger.info("Discovery complete: %d assets across %d hosts", len(assets), len(all_hosts))
    return assets
