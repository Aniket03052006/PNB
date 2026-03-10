"""
Q-ARMOR Phase 1 — Network Prober.

Synchronous TLS handshake using Python's built-in ``socket`` and ``ssl``
modules.  Extracts the negotiated TLS version, cipher suite, SNI, and
the raw DER-encoded leaf certificate for downstream parsing.

Design choices
--------------
* **No hostname verification** — ``check_hostname = False`` and
  ``verify_mode = CERT_NONE`` so that expired / self-signed certs do
  not abort the connection.  We *analyse*, we don't *trust*.
* **Strict timeout** — 5-second connect + 5-second handshake guard so
  unreachable hosts are skipped quickly.
* **Pure stdlib** — no third-party network libraries; ``cryptography``
  is only used later for cert parsing.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any, Dict, Optional, Tuple

from src.models import TLSConnectionState


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONNECT_TIMEOUT: float = 5.0   # TCP connect timeout  (seconds)
HANDSHAKE_TIMEOUT: float = 5.0 # TLS handshake timeout (seconds)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def probe_target(
    target: str,
    port: int = 443,
    timeout: float = CONNECT_TIMEOUT,
) -> Tuple[TLSConnectionState, Optional[bytes]]:
    """Probe a single *target:port* and return connection state + DER cert.

    Parameters
    ----------
    target : str
        Hostname or IP address to connect to.
    port : int
        TCP port (default 443).
    timeout : float
        Socket timeout in seconds.

    Returns
    -------
    tuple[TLSConnectionState, bytes | None]
        A populated ``TLSConnectionState`` dataclass and the raw
        DER-encoded leaf certificate (or ``None`` if unavailable).

    Raises
    ------
    ConnectionError
        Wraps all network / SSL failures so callers need only one
        ``except`` clause.
    """
    state = TLSConnectionState(
        target=target,
        port=port,
        sni=target,     # SNI = the hostname we send during the handshake
    )
    cert_der: Optional[bytes] = None

    # ------------------------------------------------------------------
    # 1.  Resolve the target to an IP (for logging / reporting)
    # ------------------------------------------------------------------
    try:
        ip_address = socket.gethostbyname(target)
        state.ip_address = ip_address
    except socket.gaierror as exc:
        raise ConnectionError(
            f"DNS resolution failed for {target}: {exc}"
        ) from exc

    # ------------------------------------------------------------------
    # 2.  Build an SSL context that accepts *any* cert
    # ------------------------------------------------------------------
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Request the widest range of protocols so we can observe what the
    # server actually negotiates.
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    # ------------------------------------------------------------------
    # 3.  TCP connect
    # ------------------------------------------------------------------
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    try:
        raw_sock.connect((ip_address, port))
    except (socket.timeout, OSError) as exc:
        raw_sock.close()
        raise ConnectionError(
            f"TCP connection to {target}:{port} failed: {exc}"
        ) from exc

    # ------------------------------------------------------------------
    # 4.  TLS handshake (wrap the existing TCP socket)
    # ------------------------------------------------------------------
    try:
        ssl_sock = ctx.wrap_socket(
            raw_sock,
            server_hostname=target,       # SNI extension
        )
        ssl_sock.settimeout(HANDSHAKE_TIMEOUT)
        ssl_sock.do_handshake()
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        raw_sock.close()
        raise ConnectionError(
            f"TLS handshake with {target}:{port} failed: {exc}"
        ) from exc

    # ------------------------------------------------------------------
    # 5.  Extract connection-level data
    # ------------------------------------------------------------------
    try:
        # Negotiated TLS version  (e.g. "TLSv1.3")
        state.tls_version = ssl_sock.version() or ""

        # Cipher tuple: (name, protocol, bits)
        cipher_info: Tuple[str, str, int] | None = ssl_sock.cipher()
        if cipher_info:
            state.cipher_suite = cipher_info[0]
            state.cipher_protocol = cipher_info[1]
            state.cipher_bits = cipher_info[2]

        # Leaf certificate in DER form (binary)
        cert_der = ssl_sock.getpeercert(binary_form=True)
    except Exception:
        # Non-fatal — we already got *some* data; keep going
        pass
    finally:
        try:
            ssl_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        ssl_sock.close()

    return state, cert_der
