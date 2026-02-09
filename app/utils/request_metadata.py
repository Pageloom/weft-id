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
from ua_parser import parse


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

    Uses ua-parser to extract device, browser, and OS information,
    then applies heuristics to determine the device type.

    Args:
        user_agent_string: Full user agent string

    Returns:
        Device description (e.g., "Mobile iPhone Safari", "Desktop Chrome") or None
    """
    if not user_agent_string:
        return None

    try:
        parsed = parse(user_agent_string)

        # Use with_defaults() to handle None values gracefully
        result = parsed.with_defaults()

        parts = []
        ua_lower = user_agent_string.lower()

        # Extract OS, device, and browser families
        os_family = result.os.family if result.os else "Other"
        device_family = result.device.family if result.device else "Other"
        browser_family = result.user_agent.family if result.user_agent else "Other"

        # Device type detection heuristics
        # Check for bots first (highest priority)
        if any(bot_hint in ua_lower for bot_hint in ("bot", "spider", "crawler", "crawl")):
            parts.append("Bot")
        # Check for tablets (iPad or Android tablets)
        elif "ipad" in ua_lower or ("tablet" in ua_lower and "android" in ua_lower):
            parts.append("Tablet")
        # Check for mobile devices (iOS/Android phones)
        elif os_family in ("iOS", "Android") or "mobile" in ua_lower:
            parts.append("Mobile")
        # Check for desktop operating systems
        elif os_family in ("Mac OS X", "Windows", "Linux", "Chrome OS", "Ubuntu"):
            parts.append("Desktop")

        # Add device family if meaningful (not generic "Other" or "Mac")
        if device_family and device_family not in ("Other", "Mac", "Spider"):
            parts.append(device_family)

        # Add browser family if available
        if browser_family and browser_family != "Other":
            parts.append(browser_family)

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

    IMPORTANT: This must match PostgreSQL's jsonb::text output format exactly.
    PostgreSQL stores JSONB keys in a specific order (not alphabetical).

    For compatibility with existing database records created by migration 00015,
    we manually construct the JSON string to match PostgreSQL's format:
    - Keys in PostgreSQL's order (not alphabetical)
    - Spaces after colons and commas
    - Format: {"key": value, "key2": value2}

    Args:
        metadata: Metadata dictionary (must include 4 required fields)

    Returns:
        MD5 hash as hex string (32 characters)
    """
    # PostgreSQL's jsonb::text produces keys in this specific order for our metadata:
    # device, user_agent, remote_address, session_id_hash
    # (plus any custom keys alphabetically after)

    # Extract the 4 required base keys in PostgreSQL's order
    base_keys_in_pg_order = ["device", "user_agent", "remote_address", "session_id_hash"]

    # Get custom keys (anything not in base keys) and sort them alphabetically
    custom_keys = sorted([k for k in metadata.keys() if k not in base_keys_in_pg_order])

    # Combine: base keys in PG order + custom keys alphabetically
    all_keys_ordered = base_keys_in_pg_order + custom_keys

    # Manually construct JSON string matching PostgreSQL's format
    pairs = []
    for key in all_keys_ordered:
        if key not in metadata:
            continue  # Skip if key doesn't exist (though all base keys should exist)
        value = metadata[key]
        # Convert value to JSON
        if value is None:
            value_str = "null"
        elif isinstance(value, bool):
            value_str = "true" if value else "false"
        elif isinstance(value, str):
            value_str = json.dumps(value)  # Properly escape strings
        elif isinstance(value, int | float):
            value_str = str(value)
        elif isinstance(value, dict):
            value_str = json.dumps(value, sort_keys=True)
        elif isinstance(value, list):
            value_str = json.dumps(value)
        else:
            value_str = json.dumps(value)

        pairs.append(f'"{key}": {value_str}')

    json_str = "{" + ", ".join(pairs) + "}"

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
