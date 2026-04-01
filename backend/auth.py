"""Supabase-backed authentication helpers for Q-ARMOR."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests
from dotenv import load_dotenv
from fastapi import HTTPException, Request, status
from jose import JWTError, jwt

logger = logging.getLogger("qarmor.auth")

load_dotenv()

SUPABASE_URL = os.environ.get(
    "SUPABASE_URL",
    "https://bfmkinyyoevrbqgpuzwx.supabase.co",
).rstrip("/")
JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
SUPABASE_ISSUER = f"{SUPABASE_URL}/auth/v1"
SUPABASE_AUDIENCE = os.environ.get("SUPABASE_JWT_AUDIENCE", "authenticated")
SUPABASE_DB_URL = os.environ.get("SUPABASE_DB_URL", "").strip()
SUPABASE_PUBLISHABLE_KEY = os.environ.get(
    "SUPABASE_PUBLISHABLE_KEY",
    os.environ.get("SUPABASE_ANON_KEY", ""),
).strip()
SUPABASE_TOKEN_STORAGE_KEY = os.environ.get("SUPABASE_TOKEN_STORAGE_KEY", "token").strip() or "token"
JWKS_CACHE_TTL_SECONDS = int(os.environ.get("SUPABASE_JWKS_CACHE_TTL_SECONDS", "3600"))

_jwks_cache: dict[str, Any] = {"payload": None, "expires_at": 0.0}


class AuthConfigurationError(RuntimeError):
    """Raised when auth settings are missing or malformed."""


def get_public_auth_config() -> dict[str, Any]:
    missing: list[str] = []
    if not SUPABASE_URL:
        missing.append("SUPABASE_URL")
    if not SUPABASE_PUBLISHABLE_KEY:
        missing.append("SUPABASE_PUBLISHABLE_KEY")

    return {
        "configured": not missing,
        "missing": missing,
        "supabaseUrl": SUPABASE_URL or None,
        "supabasePublishableKey": SUPABASE_PUBLISHABLE_KEY or None,
        "tokenStorageKey": SUPABASE_TOKEN_STORAGE_KEY,
    }


def _auth_error(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _get_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise _auth_error("Missing Authorization header")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _auth_error("Invalid Authorization header")
    return token.strip()


def _fetch_jwks(force_refresh: bool = False) -> dict[str, Any]:
    now = time.time()
    cached_payload = _jwks_cache.get("payload")
    cached_expires_at = float(_jwks_cache.get("expires_at") or 0.0)
    if cached_payload and not force_refresh and cached_expires_at > now:
        return cached_payload

    try:
        response = requests.get(JWKS_URL, timeout=10)
        response.raise_for_status()
        jwks = response.json()
    except requests.RequestException as exc:
        logger.exception("Unable to fetch Supabase JWKS")
        raise AuthConfigurationError("Unable to fetch Supabase signing keys") from exc

    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise AuthConfigurationError("Supabase JWKS response did not include signing keys")

    _jwks_cache["payload"] = jwks
    _jwks_cache["expires_at"] = now + JWKS_CACHE_TTL_SECONDS
    return jwks


def _select_signing_key(token: str) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise _auth_error("Invalid token header") from exc

    kid = header.get("kid")
    if not kid:
        raise _auth_error("Token is missing a signing key identifier")

    for force_refresh in (False, True):
        jwks = _fetch_jwks(force_refresh=force_refresh)
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return key

    raise _auth_error("Unable to match token signing key")


def verify_token(token: str) -> dict[str, Any]:
    """Validate a Supabase access token and return its payload."""
    key = _select_signing_key(token)
    algorithm = str(key.get("alg") or "RS256").strip().upper()

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            audience=SUPABASE_AUDIENCE,
            issuer=SUPABASE_ISSUER,
        )
    except JWTError as exc:
        raise _auth_error("Invalid or expired token") from exc

    return payload


def get_current_user(request: Request) -> dict[str, Any]:
    cached_user = getattr(request.state, "user", None)
    if isinstance(cached_user, dict):
        return cached_user

    token = _get_bearer_token(request.headers.get("Authorization"))
    payload = verify_token(token)
    request.state.user = payload
    return payload


def _connect_db():
    if not SUPABASE_DB_URL:
        raise AuthConfigurationError("SUPABASE_DB_URL is required for role lookups")
    try:
        import psycopg2
    except ImportError as exc:
        raise AuthConfigurationError("psycopg2 is required for role lookups") from exc
    return psycopg2.connect(SUPABASE_DB_URL, connect_timeout=10)


def get_user_role(user_id: str) -> str | None:
    with _connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT role FROM profiles WHERE id = %s", (user_id,))
            row = cur.fetchone()
    return row[0] if row else None


def require_admin(request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    user_id = str(user.get("sub") or "").strip()
    if not user_id:
        raise _auth_error("Token payload is missing subject")

    role = get_user_role(user_id)
    request.state.user_role = role
    if role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    return user


def get_user_context(request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    user_id = str(user.get("sub") or "").strip()
    role = getattr(request.state, "user_role", None)
    if role is None and user_id and SUPABASE_DB_URL:
        role = get_user_role(user_id)
        request.state.user_role = role

    return {
        "user_id": user_id,
        "email": user.get("email"),
        "role": role,
        "aud": user.get("aud"),
        "issuer": user.get("iss"),
        "expires_at": user.get("exp"),
    }
