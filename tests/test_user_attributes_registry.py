"""Tests for the standard user attribute registry and its serialization layer."""

from __future__ import annotations

import pytest
from constants.user_attributes import (
    ATTRIBUTE_KEYS,
    ATTRIBUTES_BY_KEY,
    CATEGORIES,
    STANDARD_ATTRIBUTES,
    AttributeValueError,
    attributes_by_category,
    deserialize,
    get_attribute,
    is_standard_attribute,
    serialize,
)

# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------


def test_registry_has_fourteen_attributes():
    assert len(STANDARD_ATTRIBUTES) == 14


def test_registry_keys_are_unique():
    keys = [a.key for a in STANDARD_ATTRIBUTES]
    assert len(keys) == len(set(keys))


def test_friendly_names_are_unique():
    names = [a.default_friendly_name for a in STANDARD_ATTRIBUTES]
    assert len(names) == len(set(names))


def test_required_keys_present():
    expected = {
        # contact
        "phone_work",
        "phone_mobile",
        # professional
        "display_name",
        "job_title",
        "department",
        "organization",
        "employee_id",
        # location
        "street_address",
        "city",
        "state",
        "postal_code",
        "country",
        # profile
        "preferred_language",
        "description",
    }
    assert ATTRIBUTE_KEYS == expected


def test_categories_only_contain_known_values():
    for a in STANDARD_ATTRIBUTES:
        assert a.category in CATEGORIES


def test_attributes_by_category_returns_registry_order():
    for cat in CATEGORIES:
        items = attributes_by_category(cat)
        assert all(a.category == cat for a in items)
    # Sanity: all attributes accounted for via partitioning
    total = sum(len(attributes_by_category(c)) for c in CATEGORIES)
    assert total == len(STANDARD_ATTRIBUTES)


def test_get_attribute_lookup():
    a = get_attribute("job_title")
    assert a.category == "professional"
    assert a.default_friendly_name == "jobTitle"


def test_get_attribute_unknown_raises():
    with pytest.raises(KeyError):
        get_attribute("not_a_real_attr")


def test_is_standard_attribute():
    assert is_standard_attribute("phone_work") is True
    assert is_standard_attribute("nope") is False


def test_attributes_by_key_matches_registry():
    assert set(ATTRIBUTES_BY_KEY) == ATTRIBUTE_KEYS
    assert all(ATTRIBUTES_BY_KEY[k].key == k for k in ATTRIBUTE_KEYS)


def test_max_lengths_match_documented_standards():
    # Length conventions per CLAUDE.md best-practice 10
    assert get_attribute("country").max_length == 2
    assert get_attribute("postal_code").max_length == 20
    assert get_attribute("phone_work").max_length == 50
    assert get_attribute("phone_mobile").max_length == 50
    assert get_attribute("preferred_language").max_length == 10
    assert get_attribute("description").max_length == 2000
    assert get_attribute("display_name").max_length == 255
    assert get_attribute("job_title").max_length == 255


# ---------------------------------------------------------------------------
# Serialization round-trips
# ---------------------------------------------------------------------------


def test_serialize_string_attribute_strips_whitespace():
    assert serialize("job_title", "  Engineer  ") == "Engineer"


def test_serialize_country_uppercases_and_validates():
    assert serialize("country", "us") == "US"
    assert serialize("country", "Se") == "SE"
    with pytest.raises(AttributeValueError):
        serialize("country", "USA")  # 3 letters
    with pytest.raises(AttributeValueError):
        serialize("country", "1A")  # not letters


def test_serialize_locale_canonicalizes_region():
    assert serialize("preferred_language", "en") == "en"
    assert serialize("preferred_language", "EN-us") == "en-US"
    assert serialize("preferred_language", "pt-br") == "pt-BR"
    with pytest.raises(AttributeValueError):
        serialize("preferred_language", "english")
    with pytest.raises(AttributeValueError):
        serialize("preferred_language", "_invalid_")


def test_serialize_phone_allows_common_punctuation():
    assert serialize("phone_work", "+1 (555) 123-4567") == "+1 (555) 123-4567"
    assert serialize("phone_mobile", "555.555.5555 x42") == "555.555.5555 x42"
    with pytest.raises(AttributeValueError):
        serialize("phone_work", "abc-1234")


def test_serialize_phone_requires_at_least_one_digit():
    """Pure-punctuation 'phone' values are rejected -- a phone needs a digit."""
    for bogus in ("xxx", "+++", "().", "----", "  x  "):
        with pytest.raises(AttributeValueError):
            serialize("phone_work", bogus)


def test_serialize_postal_code_allows_alphanumeric():
    assert serialize("postal_code", "12345") == "12345"
    assert serialize("postal_code", "K1A 0B1") == "K1A 0B1"  # Canadian
    assert serialize("postal_code", "SW1A 1AA") == "SW1A 1AA"  # UK
    with pytest.raises(AttributeValueError):
        serialize("postal_code", "12345!")


def test_serialize_rejects_empty_after_strip():
    with pytest.raises(AttributeValueError):
        serialize("job_title", "   ")


def test_serialize_rejects_oversized_value():
    with pytest.raises(AttributeValueError):
        serialize("country", "ABC")  # max_length=2, regex would fire first
    with pytest.raises(AttributeValueError):
        serialize("display_name", "x" * 256)


def test_serialize_rejects_unknown_key():
    with pytest.raises(KeyError):
        serialize("not_a_real_attr", "x")


def test_serialize_rejects_non_string_value():
    with pytest.raises(AttributeValueError):
        serialize("job_title", 123)  # type: ignore[arg-type]


def test_deserialize_round_trips_for_every_attribute():
    samples = {
        "phone_work": "+1 (555) 123-4567",
        "phone_mobile": "555-555-5555",
        "display_name": "Jane Doe",
        "job_title": "Engineer",
        "department": "Platform",
        "organization": "Acme",
        "employee_id": "E12345",
        "street_address": "1 Infinite Loop",
        "city": "Cupertino",
        "state": "CA",
        "postal_code": "95014",
        "country": "us",
        "preferred_language": "en-us",
        "description": "About me.",
    }
    expected = {
        **samples,
        "country": "US",
        "preferred_language": "en-US",
    }
    for key, raw in samples.items():
        stored = serialize(key, raw)
        # deserialize should be idempotent on already-serialized values
        assert deserialize(key, stored) == stored
        assert stored == expected[key]
