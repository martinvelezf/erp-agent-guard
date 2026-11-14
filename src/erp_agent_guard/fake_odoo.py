"""A tiny in-memory imitation of Odoo's ``/jsonrpc`` endpoint.

For tests and demos only: synthetic data, a single hard-coded login,
and a small domain evaluator. It is not Odoo and does not try to be.
"""

from __future__ import annotations

import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEMO_DB = "demo"
DEMO_USER = "agent-gateway"
DEMO_KEY = "fake-key-for-tests-only"

SEED: dict[str, dict[int, dict]] = {
    "res.partner": {
        1: {"name": "Andes Hardware S.A.", "email": "billing@andes-hw.example", "phone": "+593 2 555 0101",
            "vat": "1790011122001", "country_code": "EC", "customer_rank": 3, "credit_limit": 5000.0,
            "comment": "Pays on time"},
        2: {"name": "Lucia Paredes", "email": "lucia.paredes@mail.example", "phone": "+593 99 555 0199",
            "vat": "1712345678", "country_code": "EC", "customer_rank": 1, "credit_limit": 800.0,
            "comment": ""},
        3: {"name": "Pacific Imports LLC", "email": "ap@pacific-imports.example", "phone": "+1 305 555 0142",
            "vat": "US-99-0001", "country_code": "US", "customer_rank": 0, "credit_limit": 0.0,
            "comment": "Vendor"},
    },
    "sale.order": {
        10: {"name": "S00010", "partner_id": 1, "amount_total": 1250.5, "state": "sale", "note": ""},
        11: {"name": "S00011", "partner_id": 2, "amount_total": 89.9, "state": "draft", "note": ""},
    },
    "res.users": {
        2: {"name": "Administrator", "login": "admin", "password": "not-a-real-password"},
    },
    "ir.config_parameter": {
        1: {"key": "database.secret", "value": "synthetic-secret"},
    },
}

MANY2ONE = {("sale.order", "partner_id"): "res.partner"}


class FakeOdoo:
    """The in-memory database plus a JSON-RPC HTTP server around it."""

    def __init__(self, data: dict | None = None):
        self.data = copy.deepcopy(data if data is not None else SEED)
        self.calls: list[tuple[str, str]] = []  # (model, method) log for assertions
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ---- domain evaluation (subset) ----------------------------------
    @staticmethod
    def _match_term(rec: dict, term) -> bool:
        f, op, v = term
        x = rec.get(f)
        if isinstance(x, list):
            x = x[0]
        if op == "=":
            return x == v
        if op == "!=":
            return x != v
        if op in (">", ">=", "<", "<="):
            if x is None or x is False:
                return False
            return {">": x > v, ">=": x >= v, "<": x < v, "<=": x <= v}[op]
        if op in ("in", "not in"):
            r = x in v
            return r if op == "in" else not r
        if op in ("ilike", "like", "not ilike", "not like"):
            r = str(v).lower() in str(x or "").lower() if "ilike" in op else str(v) in str(x or "")
            return not r if op.startswith("not") else r
        if op in ("=ilike", "=like"):
            import fnmatch
            pat = str(v).replace("%", "*").replace("_", "?")
            return fnmatch.fnmatch(str(x or "").lower(), pat.lower()) if op == "=ilike" else fnmatch.fnmatchcase(str(x or ""), pat)
        raise ValueError(f"fake odoo: unsupported operator {op}")

    def _match(self, rec: dict, domain: list) -> bool:
        # Prefix notation with implicit '&'.
        def parse(i):
            tok = domain[i]
            if tok == "!":
                val, j = parse(i + 1)
                return (not val), j
            if tok in ("&", "|"):
                a, j = parse(i + 1)
                b, k = parse(j)
                return (a and b) if tok == "&" else (a or b), k
            return self._match_term(rec, tok), i + 1

        i, ok = 0, True
        while i < len(domain):
            val, i = parse(i)
            ok = ok and val
        return ok

    def _render(self, model: str, rid: int, fields: list[str]) -> dict:
        rec = self.data[model][rid]
        out = {"id": rid}
        for f in fields or list(rec):
            if f not in rec:
                raise KeyError(f"Invalid field '{f}' on model '{model}'")
            v = rec[f]
            target = MANY2ONE.get((model, f))
            if target and v:
                v = [v, self.data[target][v]["name"]]
            out[f] = v
        return out

    # ---- ORM-ish methods -----------------------------------------------
    def execute_kw(self, model: str, method: str, args: list, kwargs: dict):
        self.calls.append((model, method))
        if model not in self.data:
            raise KeyError(f"Object {model} doesn't exist")
        table = self.data[model]
        if method == "search_read":
            domain = args[0] if args else kwargs.get("domain", [])
            ids = [i for i in sorted(table) if self._match(table[i], domain)]
            order = kwargs.get("order")
            if order:
                f, _, d = order.split(",")[0].strip().partition(" ")
                ids.sort(key=lambda i: (table[i].get(f) is None, table[i].get(f)), reverse=d.strip().lower() == "desc")
            off, lim = kwargs.get("offset", 0), kwargs.get("limit")
            ids = ids[off: off + lim if lim else None]
            return [self._render(model, i, kwargs.get("fields") or []) for i in ids]
        if method == "read":
            return [self._render(model, i, kwargs.get("fields") or []) for i in args[0] if i in table]
        if method == "write":
            ids, vals = args
            for i in ids:
                if i not in table:
                    raise KeyError(f"Record {model}({i}) does not exist")
                table[i].update(vals)
            return True
        if method == "create":
            vals = args[0]
            new_id = max(table, default=0) + 1
            table[new_id] = {**vals}
            return new_id
        raise KeyError(f"fake odoo: method {method} not implemented")

    def dispatch(self, payload: dict):
        p = payload.get("params") or {}
        service, method, args = p.get("service"), p.get("method"), p.get("args") or []
        if service == "common" and method == "login":
            db, user, key = args
            return 7 if (db, user, key) == (DEMO_DB, DEMO_USER, DEMO_KEY) else False
        if service == "common" and method == "version":
            return {"server_version": "17.0-fake", "protocol_version": 1}
        if service == "object" and method == "execute_kw":
            db, uid, key, model, meth, margs = args[:6]
            mkw = args[6] if len(args) > 6 else {}
            if (db, uid, key) != (DEMO_DB, 7, DEMO_KEY):
                raise PermissionError("Access Denied")
            with self._lock:
                return self.execute_kw(model, meth, margs, mkw)
        raise KeyError(f"fake odoo: {service}.{method} not implemented")

    # ---- HTTP ----------------------------------------------------------
    def start(self, host: str = "127.0.0.1", port: int = 0) -> str:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def do_POST(self):
                if self.path != "/jsonrpc":
                    self.send_error(404)
                    return
                n = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(n) or b"{}")
                try:
                    body = {"jsonrpc": "2.0", "id": payload.get("id"), "result": fake.dispatch(payload)}
                except Exception as exc:
                    body = {"jsonrpc": "2.0", "id": payload.get("id"),
                            "error": {"code": 200, "message": "Odoo Server Error",
                                      "data": {"name": f"odoo.exceptions.{type(exc).__name__}",
                                               "message": str(exc),
                                               "debug": "Traceback (most recent call last): ... (fake)"}}}
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._server = ThreadingHTTPServer((host, port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        h, p = self._server.server_address[:2]
        return f"http://{h}:{p}"

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
