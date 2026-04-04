"""Cloud Provider Detection — identifies whether an IP/hostname is cloud-hosted.

Detection strategy (in order of reliability):
  1. Reverse DNS PTR record matching against known cloud provider patterns
  2. Hostname-based inference (forward hostname patterns)
  3. IP prefix heuristics for major providers (fallback only)

Returns a dict with:
  provider: str  — "aws" | "azure" | "gcp" | "cloudflare" | "fastly" |
                    "akamai" | "microsoft" | "self_hosted" | "unknown"
  is_cloud: bool
  pool: str      — "cloud" | "self_hosted"
  display_name: str
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket

logger = logging.getLogger("qarmor.cloud_detector")

# ── PTR pattern matching ─────────────────────────────────────────────────────

_PTR_PATTERNS: list[tuple[str, str]] = [
    # AWS
    ("compute.amazonaws.com", "aws"),
    ("amazonaws.com", "aws"),
    ("ec2.internal", "aws"),
    ("awsglobalaccelerator.com", "aws"),
    ("cloudfront.net", "aws"),
    ("elb.amazonaws.com", "aws"),
    # Azure / Microsoft
    ("cloudapp.azure.com", "azure"),
    ("azure.com", "azure"),
    ("trafficmanager.net", "azure"),
    ("azurewebsites.net", "azure"),
    ("microsoft.com", "microsoft"),
    ("msftnet.com", "microsoft"),
    # GCP
    ("cloud.google.com", "gcp"),
    ("googleusercontent.com", "gcp"),
    ("googleapis.com", "gcp"),
    ("google.com", "gcp"),
    # Cloudflare
    ("cloudflareworkers.com", "cloudflare"),
    ("cloudflare.com", "cloudflare"),
    ("cloudflare-dns.com", "cloudflare"),
    # Fastly
    ("fastly.net", "fastly"),
    ("fastlylb.net", "fastly"),
    ("fastly-ip.net", "fastly"),
    # Akamai
    ("akamaiedge.net", "akamai"),
    ("akamai.net", "akamai"),
    ("akamaized.net", "akamai"),
    ("edgekey.net", "akamai"),
    # DigitalOcean
    ("digitalocean.com", "digitalocean"),
    ("digitaloceanspaces.com", "digitalocean"),
    # Oracle Cloud
    ("oraclecloud.com", "oracle"),
    # Alibaba
    ("aliyuncs.com", "alibaba"),
]

# ── Hostname-based forward patterns ─────────────────────────────────────────

_HOSTNAME_PATTERNS: list[tuple[str, str]] = [
    ("amazonaws.com", "aws"),
    ("awsglobalaccelerator.com", "aws"),
    ("cloudfront.net", "aws"),
    ("azure.com", "azure"),
    ("azurewebsites.net", "azure"),
    ("microsoft.com", "microsoft"),
    ("trafficmanager.net", "azure"),
    ("googleapis.com", "gcp"),
    ("googleusercontent.com", "gcp"),
    ("cloud.google.com", "gcp"),
    ("cloudflare.com", "cloudflare"),
    ("fastly.net", "fastly"),
    ("akamaiedge.net", "akamai"),
    ("akamai.net", "akamai"),
    ("digitalocean.com", "digitalocean"),
    ("oraclecloud.com", "oracle"),
    ("aliyuncs.com", "alibaba"),
]

# ── IP prefix heuristics (last resort — imprecise) ───────────────────────────

_IP_PREFIX_MAP: list[tuple[tuple[str, ...], str]] = [
    # AWS — major ranges
    (("3.", "52.", "54.", "13.", "18.", "35.180.", "35.181.",
      "35.182.", "35.183.", "35.184.", "35.185.", "35.186."), "aws"),
    # Azure
    (("40.", "20.", "51.", "104.40.", "104.41.", "104.42.",
      "104.43.", "104.44.", "104.45.", "104.46.", "104.47.",
      "104.208.", "104.209.", "104.210.", "104.211.",
      "137.116.", "137.117.", "137.135."), "azure"),
    # GCP
    (("34.", "35.", "104.196.", "104.197.", "104.198.",
      "104.199.", "104.154.", "104.155."), "gcp"),
    # Cloudflare
    (("104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
      "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
      "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.",
      "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
      "172.70.", "172.71.", "141.101.", "108.162.", "190.93."), "cloudflare"),
    # Fastly
    (("151.101.", "199.27.", "23.235.", "103.244."), "fastly"),
    # DigitalOcean
    (("165.22.", "157.245.", "138.197.", "167.172.", "206.189.",
      "64.225.", "68.183."), "digitalocean"),
]

_DISPLAY_NAMES: dict[str, str] = {
    "aws": "Amazon AWS",
    "azure": "Microsoft Azure",
    "microsoft": "Microsoft",
    "gcp": "Google Cloud",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly CDN",
    "akamai": "Akamai CDN",
    "digitalocean": "DigitalOcean",
    "oracle": "Oracle Cloud",
    "alibaba": "Alibaba Cloud",
    "self_hosted": "Self-Hosted",
    "unknown": "Unknown",
}


def _result(provider: str) -> dict:
    is_cloud = provider not in ("self_hosted", "unknown")
    return {
        "provider": provider,
        "display_name": _DISPLAY_NAMES.get(provider, provider.title()),
        "is_cloud": is_cloud,
        "pool": "cloud" if is_cloud else "self_hosted",
    }


def _match_ptr(ptr: str) -> str | None:
    ptr_lower = ptr.lower()
    for suffix, provider in _PTR_PATTERNS:
        if ptr_lower.endswith(suffix) or suffix in ptr_lower:
            return provider
    return None


def _match_hostname(hostname: str) -> str | None:
    h = hostname.lower()
    for suffix, provider in _HOSTNAME_PATTERNS:
        if h.endswith(suffix) or suffix in h:
            return provider
    return None


def _match_ip_prefix(ip: str) -> str | None:
    for prefixes, provider in _IP_PREFIX_MAP:
        if any(ip.startswith(p) for p in prefixes):
            return provider
    return None


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


async def detect_cloud_provider(ip: str, hostname: str | None = None) -> dict:
    """Detect cloud provider for a given IP address.

    Returns dict with: provider, display_name, is_cloud, pool.
    Never raises — returns {"provider": "unknown", ...} on any error.
    """
    try:
        if not ip:
            if hostname:
                m = _match_hostname(hostname)
                if m:
                    return _result(m)
            return _result("unknown")

        # Private/RFC1918 → self-hosted
        if _is_private_ip(ip):
            return _result("self_hosted")

        # Step 1: Hostname pattern (fast, no I/O)
        if hostname:
            m = _match_hostname(hostname)
            if m:
                return _result(m)

        # Step 2: Reverse DNS lookup
        try:
            ptr = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, socket.gethostbyaddr, ip
                ),
                timeout=3.0,
            )
            # ptr is (hostname, aliases, addresses)
            ptr_name = ptr[0] if ptr else ""
            if ptr_name:
                m = _match_ptr(ptr_name)
                if m:
                    return _result(m)
        except (asyncio.TimeoutError, socket.herror, OSError):
            pass

        # Step 3: IP prefix heuristic (fallback)
        m = _match_ip_prefix(ip)
        if m:
            return _result(m)

        return _result("self_hosted")

    except Exception as exc:
        logger.debug("Cloud detection error for %s: %s", ip, exc)
        return _result("unknown")


def group_ips_by_subnet(ips: list[str]) -> dict[str, list[str]]:
    """Group IP addresses by /24 subnet (first 3 octets).

    Returns {"103.107.224": ["103.107.224.11", "103.107.224.29"], ...}
    """
    groups: dict[str, list[str]] = {}
    for ip in ips:
        parts = ip.split(".")
        if len(parts) == 4:
            subnet = ".".join(parts[:3])
            groups.setdefault(subnet, []).append(ip)
    return groups
