"""Odoo external API over JSON-RPC (``/jsonrpc``), stdlib only.

Credentials come from the environment, never from the agent:
``ODOO_URL``, ``ODOO_DB``, ``ODOO_USER``, ``ODOO_API_KEY``.
Use a dedicated Odoo user with minimal ACLs: the gateway is a second
layer on top of Odoo's own access rules, not a replacement for them.
"""

from __future__ import annotations

import itertools
import json
import os
import urllib.error
import urllib.request
from typing import Any

from ..errors import UpstreamError


class OdooJsonRpcAdapter:
    name = "odoo"

    def __init__(self, url: str, db: str, user: str, api_key: str, timeout: float = 30.0):
        self.url = url.rstrip("/") + "/jsonrpc"
        self.db = db
        self.user = user
        self._key = api_key
        self.timeout = timeout
        self._uid: int | None = None
        self._ids = itertools.count(1)

    def __repr__(self) -> str:  # never leak the key in tracebacks/logs
        return f"OdooJsonRpcAdapter(url={self.url!r}, db={self.db!r}, user={self.user!r})"

    @classmethod
    def from_env(cls) -> "OdooJsonRpcAdapter":
        missing = [k for k in ("ODOO_URL", "ODOO_DB", "ODOO_USER", "ODOO_API_KEY") if not os.environ.get(k)]
        if missing:
            raise UpstreamError(f"missing environment variables: {', '.join(missing)}")
        return cls(os.environ["ODOO_URL"], os.environ["ODOO_DB"], os.environ["ODOO_USER"], os.environ["ODOO_API_KEY"])

    def _rpc(self, service: str, method: str, args: list) -> Any:
        payload = {"jsonrpc": "2.0", "method": "call",
                   "params": {"service": service, "method": method, "args": args},
                   "id": next(self._ids)}
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise UpstreamError(f"cannot reach ERP: {type(exc).__name__}") from None
        if "error" in body:
            err = body["error"] or {}
            data = err.get("data") or {}
            # Do not forward Odoo debug tracebacks to the agent.
            name = data.get("name") or "odoo.error"
            msg = (data.get("message") or err.get("message") or "error")[:300]
            raise UpstreamError(f"{name}: {msg}")
        return body.get("result")

    @property
    def uid(self) -> int:
        if self._uid is None:
            uid = self._rpc("common", "login", [self.db, self.user, self._key])
            if not uid:
                raise UpstreamError("authentication to ERP failed")
            self._uid = int(uid)
        return self._uid

    def _call(self, model: str, method: str, args: list, kwargs: dict | None = None) -> Any:
        return self._rpc("object", "execute_kw", [self.db, self.uid, self._key, model, method, args, kwargs or {}])

    def search_read(self, model, domain, fields, limit, offset=0, order=None):
        kw = {"fields": list(fields), "limit": limit, "offset": offset}
        if order:
            kw["order"] = order
        return self._call(model, "search_read", [domain], kw)

    def read(self, model, ids, fields):
        return self._call(model, "read", [list(ids)], {"fields": list(fields)})

    def write(self, model, ids, values):
        return bool(self._call(model, "write", [list(ids), values]))

    def create(self, model, values):
        return int(self._call(model, "create", [values]))
