"""PII masking applied to values before they leave the gateway."""

from __future__ import annotations

import hashlib
from typing import Any


def _mask_email(v: str) -> str:
    local, sep, domain = v.partition("@")
    if not sep:
        return "[REDACTED]"
    head = local[:1] if local else ""
    return f"{head}***@{domain}"


def _mask_last4(v: str) -> str:
    digits = "".join(ch for ch in v if ch.isalnum())
    if len(digits) <= 4:
        return "****"
    return "***" + digits[-4:]


def _mask_initials(v: str) -> str:
    parts = [p for p in v.replace("-", " ").split() if p]
    return " ".join(p[0].upper() + "." for p in parts) or "[REDACTED]"


def mask_value(value: Any, strategy: str, salt: str = "") -> Any:
    """Mask a single value. ``False``/``None`` (Odoo's "empty") pass through."""
    if value is None or value is False:
        return value
    if strategy == "redact":
        return "[REDACTED]"
    # Many2one values arrive as [id, display_name]: mask the name only.
    if isinstance(value, list) and len(value) == 2 and isinstance(value[0], int):
        return [value[0], mask_value(value[1], strategy, salt)]
    text = str(value)
    if strategy == "email":
        return _mask_email(text)
    if strategy == "last4":
        return _mask_last4(text)
    if strategy == "initials":
        return _mask_initials(text)
    if strategy == "hash":
        digest = hashlib.sha256((salt + "\x00" + text).encode()).hexdigest()
        return "h:" + digest[:16]
    raise ValueError(f"unknown mask strategy {strategy!r}")


def mask_record(record: dict, masks: dict[str, str], salt: str = "") -> dict:
    return {k: (mask_value(v, masks[k], salt) if k in masks else v) for k, v in record.items()}
