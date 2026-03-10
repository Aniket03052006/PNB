"""Module 1: Asset Discovery — DNS enumeration, CT logs, port scanning."""

from __future__ import annotations
import socket
import ssl
import httpx
import asyncio
from backend.models import DiscoveredAsset, AssetType


COMMON_SUBDOMAINS = [
    "www", "api", "mail", "vpn", "remote", "gateway", "portal",
    "secure", "login", "auth", "admin", "app", "mobile", "mobileapi",
    "banking", "netbanking", "ibanking", "ib", "corporate", "corp",
    "pay", "payment", "payments", "upi", "neft", "rtgs", "imps",
    "cdn", "static", "assets", "media", "docs", "developer",
    "staging", "stage", "dev", "test", "uat", "sandbox",
    "smtp", "imap", "pop", "exchange", "mx",
    "ftp", "sftp",
]

SCAN_PORTS = [80, 443, 8080, 8443, 4433, 1194, 500, 4500]


async def enumerate_subdomains_dns(domain: str) -> list[str]:
    """Brute-force subdomain discovery using DNS resolution."""
    found = []
    loop = asyncio.get_event_loop()

    async def check(sub: str):
        fqdn = f"{sub}.{domain}"
        try:
            await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            found.append(fqdn)
        except socket.gaierror:
            pass

    tasks = [check(s) for s in COMMON_SUBDOMAINS]
    await asyncio.gather(*tasks)
    return sorted(set(found))


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
    except Exception:
        pass
    return sorted(subdomains)


async def scan_ports(host: str, ports: list[int] | None = None) -> list[int]:
    """Scan common ports on a host to find live services."""
    ports = ports or SCAN_PORTS
    open_ports: list[int] = []
    loop = asyncio.get_event_loop()

    async def probe(port: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = await loop.run_in_executor(None, sock.connect_ex, (host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass

    await asyncio.gather(*[probe(p) for p in ports])
    return sorted(open_ports)


def classify_asset_type(hostname: str, port: int) -> AssetType:
    """Infer asset type from hostname and port."""
    h = hostname.lower()
    if port in (1194, 500, 4500) or "vpn" in h or "remote" in h:
        return AssetType.VPN
    if "api" in h or "gateway" in h or "developer" in h:
        return AssetType.API
    if "mail" in h or "smtp" in h or "exchange" in h:
        return AssetType.MAIL
    return AssetType.WEB


async def discover_assets(
    domain: str,
    include_ct: bool = True,
    include_port_scan: bool = True,
) -> list[DiscoveredAsset]:
    """Full discovery pipeline: DNS + CT logs + port scanning."""
    all_hosts: set[str] = {domain}

    # Step 1: DNS subdomain enumeration
    dns_results = await enumerate_subdomains_dns(domain)
    all_hosts.update(dns_results)

    # Step 2: CT log query
    if include_ct:
        ct_results = await query_ct_logs(domain)
        all_hosts.update(ct_results)

    # Step 3: Build asset list with port scanning
    assets: list[DiscoveredAsset] = []
    for host in sorted(all_hosts):
        if include_port_scan:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                continue
            open_ports = await scan_ports(ip, [443, 8443, 80])
            for port in open_ports:
                assets.append(DiscoveredAsset(
                    hostname=host,
                    ip=ip,
                    port=port,
                    asset_type=classify_asset_type(host, port),
                    discovery_method="dns+ct+portscan",
                ))
        else:
            assets.append(DiscoveredAsset(
                hostname=host,
                port=443,
                asset_type=classify_asset_type(host, 443),
                discovery_method="dns+ct",
            ))

    return assets
