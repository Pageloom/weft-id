"""Standard user attribute registry.

This module is the single source of truth for the 14 standard user attributes
that flow from upstream IdPs into WeftID and out to downstream SPs.

The registry defines, per attribute:
    - key: stable identifier used in user_attributes.attribute_key and in the
      tenant_attribute_config and per-IdP / per-SP mapping JSON columns.
    - category: one of "contact", "professional", "location", "profile".
    - value_type: "string", "country" (ISO 3166-1 alpha-2), "locale" (BCP 47),
      "phone" (free-form, length-limited), or "postal_code".
    - default_friendly_name: the camelCase wire name used as the default in
      SAML mappings (preferred over OIDs for typical SaaS SPs).
    - default_oid: the canonical urn:oid: form for federation-style SPs.
    - max_length: enforced both at serialization time and via SQL CHECK
      constraints where practical.

The migration file db-init/migrations/0033_user_attributes.sql contains a
literal VALUES list mirroring this registry. Adding a 15th attribute requires
both (a) a new entry below AND (b) a follow-up migration that inserts the new
row into tenant_attribute_config for every existing tenant.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

Category = Literal["contact", "professional", "location", "profile"]
ValueType = Literal["string", "country", "locale", "phone", "postal_code"]
Source = Literal["idp", "admin", "self"]


@dataclass(frozen=True)
class StandardAttribute:
    """One entry in the standard attribute registry."""

    key: str
    category: Category
    value_type: ValueType
    default_friendly_name: str
    default_oid: str
    max_length: int


# Standard limits (per CLAUDE.md best-practice 10):
#   names/titles 255, descriptions 2000, country 2, postal_code 20,
#   phone 50, locale 10.
STANDARD_ATTRIBUTES: Final[tuple[StandardAttribute, ...]] = (
    # --- Contact -----------------------------------------------------------
    StandardAttribute(
        key="phone_work",
        category="contact",
        value_type="phone",
        default_friendly_name="phoneWork",
        default_oid="urn:oid:2.5.4.20",  # telephoneNumber
        max_length=50,
    ),
    StandardAttribute(
        key="phone_mobile",
        category="contact",
        value_type="phone",
        default_friendly_name="phoneMobile",
        default_oid="urn:oid:0.9.2342.19200300.100.1.41",  # mobile
        max_length=50,
    ),
    # --- Professional ------------------------------------------------------
    StandardAttribute(
        key="display_name",
        category="professional",
        value_type="string",
        default_friendly_name="displayName",
        default_oid="urn:oid:2.16.840.1.113730.3.1.241",
        max_length=255,
    ),
    StandardAttribute(
        key="job_title",
        category="professional",
        value_type="string",
        default_friendly_name="jobTitle",
        default_oid="urn:oid:2.5.4.12",  # title
        max_length=255,
    ),
    StandardAttribute(
        key="department",
        category="professional",
        value_type="string",
        default_friendly_name="department",
        default_oid="urn:oid:2.5.4.11",  # ou (organizationalUnit)
        max_length=255,
    ),
    StandardAttribute(
        key="organization",
        category="professional",
        value_type="string",
        default_friendly_name="organization",
        default_oid="urn:oid:2.5.4.10",  # o
        max_length=255,
    ),
    StandardAttribute(
        key="employee_id",
        category="professional",
        value_type="string",
        default_friendly_name="employeeId",
        default_oid="urn:oid:2.16.840.1.113730.3.1.3",  # employeeNumber
        max_length=255,
    ),
    # --- Location ----------------------------------------------------------
    StandardAttribute(
        key="street_address",
        category="location",
        value_type="string",
        default_friendly_name="streetAddress",
        default_oid="urn:oid:2.5.4.9",
        max_length=255,
    ),
    StandardAttribute(
        key="city",
        category="location",
        value_type="string",
        default_friendly_name="city",
        default_oid="urn:oid:2.5.4.7",  # l (locality)
        max_length=255,
    ),
    StandardAttribute(
        key="state",
        category="location",
        value_type="string",
        default_friendly_name="state",
        default_oid="urn:oid:2.5.4.8",  # st (stateOrProvince)
        max_length=255,
    ),
    StandardAttribute(
        key="postal_code",
        category="location",
        value_type="postal_code",
        default_friendly_name="postalCode",
        default_oid="urn:oid:2.5.4.17",
        max_length=20,
    ),
    StandardAttribute(
        key="country",
        category="location",
        value_type="country",
        default_friendly_name="country",
        default_oid="urn:oid:2.5.4.6",  # c (countryName, ISO 3166-1 alpha-2)
        max_length=2,
    ),
    # --- Profile -----------------------------------------------------------
    StandardAttribute(
        key="preferred_language",
        category="profile",
        value_type="locale",
        default_friendly_name="preferredLanguage",
        default_oid="urn:oid:2.16.840.1.113730.3.1.39",  # preferredLanguage
        max_length=10,
    ),
    StandardAttribute(
        key="description",
        category="profile",
        value_type="string",
        default_friendly_name="description",
        default_oid="urn:oid:2.5.4.13",
        max_length=2000,
    ),
)

# Lookup tables for O(1) access.
ATTRIBUTES_BY_KEY: Final[dict[str, StandardAttribute]] = {a.key: a for a in STANDARD_ATTRIBUTES}

ATTRIBUTE_KEYS: Final[frozenset[str]] = frozenset(ATTRIBUTES_BY_KEY)

CATEGORIES: Final[tuple[Category, ...]] = ("contact", "professional", "location", "profile")


def get_attribute(key: str) -> StandardAttribute:
    """Return the registry entry for ``key`` or raise ``KeyError``."""
    try:
        return ATTRIBUTES_BY_KEY[key]
    except KeyError as exc:
        raise KeyError(f"Unknown user attribute key: {key!r}") from exc


def is_standard_attribute(key: str) -> bool:
    """True if ``key`` is one of the 14 standard attribute keys."""
    return key in ATTRIBUTE_KEYS


def attributes_by_category(category: Category) -> tuple[StandardAttribute, ...]:
    """Return the registry entries for one category, in registry order."""
    return tuple(a for a in STANDARD_ATTRIBUTES if a.category == category)


# ----------------------------------------------------------------------------
# Serialization
# ----------------------------------------------------------------------------
# All values are stored as text in user_attributes.value. The serialize /
# deserialize pair owns per-attribute validation. The store-side type is always
# ``str``; the runtime-side type is ``str`` for the v1 set of 14 attributes
# (all scalar strings under different validation rules), but the deserialize
# return type is annotated as ``str`` so future non-string types can be added
# without API churn.

# ISO 3166-1 alpha-2: exactly two ASCII letters (case-insensitive on input,
# stored as upper case).
_COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")
# BCP 47 language tag, conservative subset: primary subtag plus optional
# region/script subtags. Length already capped at 10 by max_length.
_LOCALE_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,4})*$")
# Phone numbers: digits, spaces, dashes, parens, leading +, plus dots and the
# extension marker 'x' (e.g. "+1 (555) 123-4567 x42"). Permissive on purpose;
# the value is for display, not auto-dialing. Lookahead requires at least one
# digit so values like "xxx" or "+++" are rejected.
_PHONE_RE = re.compile(r"^(?=.*\d)[\d+\-\s().x]+$")
# Postal codes: digits, letters, spaces, dashes (covers US ZIP, ZIP+4, UK,
# Canadian, etc.). Length already capped at 20.
_POSTAL_RE = re.compile(r"^[A-Za-z0-9\s\-]+$")


class AttributeValueError(ValueError):
    """Raised when an attribute value fails validation."""


def serialize(key: str, value: str) -> str:
    """Validate and normalize ``value`` for storage in user_attributes.value.

    Raises:
        KeyError: if ``key`` is not a standard attribute.
        AttributeValueError: if ``value`` fails per-type validation.
    """
    attr = get_attribute(key)
    if value is None:  # type: ignore[unreachable]
        raise AttributeValueError(f"{key}: value must not be None")
    if not isinstance(value, str):
        raise AttributeValueError(f"{key}: value must be str, got {type(value).__name__}")

    normalized = value.strip()
    if normalized == "":
        raise AttributeValueError(f"{key}: value must not be empty after strip")
    if len(normalized) > attr.max_length:
        raise AttributeValueError(f"{key}: value exceeds max_length {attr.max_length}")

    if attr.value_type == "country":
        if not _COUNTRY_RE.match(normalized):
            raise AttributeValueError(f"{key}: must be a 2-letter ISO 3166-1 alpha-2 code")
        return normalized.upper()

    if attr.value_type == "locale":
        if not _LOCALE_RE.match(normalized):
            raise AttributeValueError(
                f"{key}: must be a BCP 47 language tag (e.g. en, en-US, pt-BR)"
            )
        # Canonical form: language lower, region upper. Conservative -- only
        # touches the obvious lang-region case; leaves rarer subtags alone.
        parts = normalized.split("-")
        parts[0] = parts[0].lower()
        if len(parts) >= 2 and len(parts[1]) in (2, 3) and parts[1].isalpha():
            parts[1] = parts[1].upper()
        return "-".join(parts)

    if attr.value_type == "phone":
        if not _PHONE_RE.match(normalized):
            raise AttributeValueError(
                f"{key}: phone may only contain digits, spaces, +, -, (), ., or x"
            )
        return normalized

    if attr.value_type == "postal_code":
        if not _POSTAL_RE.match(normalized):
            raise AttributeValueError(
                f"{key}: postal code may only contain letters, digits, spaces, and dashes"
            )
        return normalized

    # value_type == "string"
    return normalized


def deserialize(key: str, raw: str) -> str:
    """Return the typed value for ``raw`` as previously stored.

    For the v1 attribute set every value type returns ``str`` (with country
    upper-cased, locale canonicalized). Adding a non-string-typed attribute
    later means widening the return type union -- intentionally deferred until
    a real use case exists.

    Raises:
        KeyError: if ``key`` is not a standard attribute.
        AttributeValueError: if ``raw`` fails per-type validation.
    """
    # Re-run validation on read so corrupt rows surface as errors at the
    # boundary instead of silently returning bad data.
    return serialize(key, raw)
