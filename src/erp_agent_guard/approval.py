"""Approval tokens bound to one exact proposal.

A token is ``<proposal_id>.<expiry_unix>.<hmac>`` where the HMAC covers the
proposal id, the proposal digest (hash of agent, model, ids, values and the
"before" snapshot) and the expiry. A token approved for one diff cannot be
replayed for another, and the agent never holds the secret: only the human
running ``erp-agent-guard approve`` and the gateway process do.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

from .errors import ApprovalError


def get_secret(env_name: str) -> bytes:
    secret = os.environ.get(env_name, "")
    if len(secret) < 16:
        raise ApprovalError(f"approval secret missing or too short: set ${env_name} (>= 16 chars)")
    return secret.encode()


def _mac(secret: bytes, proposal_id: str, digest: str, expiry: int) -> str:
    msg = f"{proposal_id}|{digest}|{expiry}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def issue_token(secret: bytes, proposal_id: str, digest: str, ttl: int, now: float | None = None) -> str:
    expiry = int((now if now is not None else time.time()) + ttl)
    return f"{proposal_id}.{expiry}.{_mac(secret, proposal_id, digest, expiry)}"


def verify_token(secret: bytes, token: str, proposal_id: str, digest: str, now: float | None = None) -> None:
    try:
        pid, exp_s, mac = token.strip().split(".")
        expiry = int(exp_s)
    except (ValueError, AttributeError):
        raise ApprovalError("malformed approval token") from None
    if pid != proposal_id:
        raise ApprovalError("approval token belongs to a different proposal")
    expected = _mac(secret, proposal_id, digest, expiry)
    if not hmac.compare_digest(mac, expected):
        raise ApprovalError("approval token signature does not match this proposal")
    if (now if now is not None else time.time()) > expiry:
        raise ApprovalError("approval token expired")
