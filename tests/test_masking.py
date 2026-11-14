import pytest

from erp_agent_guard.masking import mask_record, mask_value


@pytest.mark.parametrize("value,strategy,expected", [
    ("lucia.paredes@mail.example", "email", "l***@mail.example"),
    ("not-an-email", "email", "[REDACTED]"),
    ("+593 99 555 0199", "last4", "***0199"),
    ("12", "last4", "****"),
    ("Lucia Paredes", "initials", "L. P."),
    ("anything", "redact", "[REDACTED]"),
    (False, "redact", False),
    (None, "email", None),
    ([4, "Lucia Paredes"], "initials", [4, "L. P."]),
])
def test_mask_value(value, strategy, expected):
    assert mask_value(value, strategy) == expected


def test_hash_is_stable_and_salted():
    a = mask_value("1712345678", "hash", salt="s1")
    assert a == mask_value("1712345678", "hash", salt="s1")
    assert a != mask_value("1712345678", "hash", salt="s2")
    assert a.startswith("h:") and "1712345678" not in a


def test_mask_record_only_touches_listed_fields():
    rec = {"id": 1, "name": "X", "email": "a@b.example"}
    assert mask_record(rec, {"email": "redact"}) == {"id": 1, "name": "X", "email": "[REDACTED]"}
