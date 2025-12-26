"""Request metadata extraction and hashing utilities for event logging.

This module provides utilities to:
1. Extract request metadata (IP, user agent, device, session) from FastAPI Request objects
2. Hash session IDs for secure storage (SHA-256)
3. Compute metadata hashes for deduplication (MD5 of deterministic JSON)

The 4 required metadata fields are:
- remote_address: IP address from headers or client
- user_agent: Full user agent string
- device: Parsed device type/name from user agent
- session_id_hash: SHA-256 hash of session ID

These fields are always present in metadata (even if null).
Individual events may add custom fields on top.
"""

import hashlib
import json
from typing import Any

from fastapi import Request
from user_agents import parse


def extract_remote_address(request: Request) -> str | None:
    """Extract IP address from request headers or client.

    Checks in order:
    1. X-Forwarded-For header (uses first IP)
    2. X-Real-IP header
    3. request.client.host

    Args:
        request: FastAPI Request object

    Returns:
        IP address string or None if unavailable
    """
    # Check X-Forwarded-For (proxy/load balancer)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first (client IP)
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP (alternative proxy header)
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    # Fall back to direct client host
    if request.client:
        return request.client.host

    return None


def parse_device_from_user_agent(user_agent_string: str | None) -> str | None:
    """Parse device information from user agent string.

    Args:
        user_agent_string: Full user agent string

    Returns:
        Device description (e.g., "iPhone", "Desktop Chrome") or None
    """
    if not user_agent_string:
        return None

    try:
        ua = parse(user_agent_string)

        # Build device description
        parts = []

        if ua.is_mobile:
            parts.append("Mobile")
        elif ua.is_tablet:
            parts.append("Tablet")
        elif ua.is_pc:
            parts.append("Desktop")
        elif ua.is_bot:
            parts.append("Bot")

        # Add device family if available
        if ua.device.family and ua.device.family != "Other":
            parts.append(ua.device.family)

        # Add browser if available
        if ua.browser.family and ua.browser.family != "Other":
            parts.append(ua.browser.family)

        return " ".join(parts) if parts else "Unknown Device"

    except Exception:
        # If parsing fails, return a safe default
        return "Unknown Device"


def hash_session_id(session_id: str | None) -> str | None:
    """Hash session ID using SHA-256 for secure storage.

    Session IDs are hashed before storage to prevent session hijacking
    if the database is compromised.

    Args:
        session_id: Raw session ID from cookie

    Returns:
        SHA-256 hash of session ID (hex string) or None if no session ID
    """
    if not session_id:
        return None

    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def compute_metadata_hash(metadata: dict[str, Any]) -> str:
    """Compute MD5 hash of metadata for deduplication.

    Uses deterministic JSON serialization to ensure consistent hashing:
    - Keys sorted alphabetically (sort_keys=True)
    - Compact format with no spaces (separators=(',', ':'))

    This must match the PostgreSQL implementation in the migration:
    md5(jsonb::text) where JSONB stores keys in sorted order.

    Args:
        metadata: Metadata dictionary (must include 4 required fields)

    Returns:
        MD5 hash as hex string (32 characters)
    """
    # Serialize with deterministic format
    json_str = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

    # Compute MD5 hash
    return hashlib.md5(json_str.encode("utf-8")).hexdigest()


def extract_request_metadata(request: Request) -> dict[str, Any]:
    """Extract full request metadata from FastAPI Request.

    Extracts the 4 required fields for event logging:
    - remote_address: IP address
    - user_agent: Full user agent string
    - device: Parsed device from user agent
    - session_id_hash: Hashed session ID

    All fields are always present (set to None if unavailable).

    Args:
        request: FastAPI Request object

    Returns:
        Dictionary with 4 required metadata fields (keys sorted alphabetically)
    """
    # Extract user agent
    user_agent = request.headers.get("user-agent")

    # Extract session ID from session cookie (if available)
    # The cookie name is "session" by default in most FastAPI session middleware
    session_id = request.cookies.get("session")

    # Build metadata with required fields (keys in alphabetical order)
    metadata = {
        "device": parse_device_from_user_agent(user_agent),
        "remote_address": extract_remote_address(request),
        "session_id_hash": hash_session_id(session_id),
        "user_agent": user_agent,
    }

    return metadata
