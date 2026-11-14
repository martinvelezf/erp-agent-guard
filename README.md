# erp-agent-guard

A policy gateway between AI agents (MCP clients) and an ERP.
The agent gets a small set of MCP tools. Every call goes through a YAML policy before it reaches the ERP:

- **Allowlists.** Models and fields must be listed. Everything else is denied, including unknown agents.
- **Read-only by default.** An agent or a model has to be switched to `read-write` explicitly.
- **Two-step writes.** `erp_propose_write` / `erp_propose_create` are dry-runs: they write nothing and return a field-by-field diff. `erp_commit` applies the change.
- **Human approval token.** The token is an HMAC over the exact diff. A person creates it with `erp-agent-guard approve <id>` after seeing the diff. The agent never holds the secret, and a token for one diff cannot commit another.
- **Stale-write check.** At commit, the gateway reads the records again and refuses if they changed since the dry-run.
- **PII masking.** Strategies are `email`, `last4`, `initials`, `hash` (salted) and `redact`. A masked field cannot be filtered or sorted on, so the agent cannot rebuild it with a search oracle such as `vat =like '17%'`.
- **Quotas.** Each agent has a calls-per-minute limit and a record-writes-per-day limit.
- **Hash-chained audit log.** The log is append-only JSONL. It records reads, denials, proposals, approvals and commits. `erp-agent-guard verify-audit` detects edited, deleted or reordered lines.
- **Built-in deny lists.** Some models and fields are always denied, whatever the YAML says. Models: `ir.config_parameter`, `ir.cron`, `ir.rule`, `res.users.apikeys`, `ir.module.module` and more. Fields: `password`, `api_key`, `totp_secret` and more.

The first adapter is **Odoo JSON-RPC** (`/jsonrpc`, Odoo 14 to 19). The guard only talks to an `ERPAdapter` interface (`search_read`, `read`, `write`, `create`), so NetSuite or another ERP can be added later (see [ROADMAP.md](ROADMAP.md)).

> Intended use: put your **own** agents in front of your **own** ERP, or one you are authorized to administer. This tool limits what an agent can do. It does not replace Odoo's own access rights, so connect it with a dedicated Odoo user that has minimal ACLs.

## Install

```bash
pip install -e .            # Python >= 3.10, depends only on PyYAML
erp-agent-guard --help
```

## Quick start

1. Write a policy. [`examples/policy.yaml`](examples/policy.yaml) is a complete one:

```yaml
version: 1
defaults: {mode: read-only, max_records: 50, quota: {calls_per_minute: 30, writes_per_day: 20}}
deny: {models: ["res.users", "hr.*"], fields: ["*_token"]}
agents:
  support-bot:
    models:
      res.partner:
        read: [name, email, phone, country_code]
        mask: {email: email, phone: last4}
  sales-ops:
    mode: read-write
    models:
      res.partner:
        read: [name, phone, comment, vat]
        write: [phone, comment]
        mask: {vat: last4}
approval: {required: true, secret_env: EAG_APPROVAL_SECRET, ttl_seconds: 900}
audit: {path: audit.jsonl}
proposals: {path: proposals.json}
```

2. Check the policy:

```bash
erp-agent-guard check-policy policy.yaml
```

3. Register the gateway as an MCP server in your client. The agent identity is fixed by `--agent` when the server starts, and the model cannot change it:

```json
{
  "mcpServers": {
    "erp": {
      "command": "erp-agent-guard",
      "args": ["serve", "--policy", "/path/policy.yaml", "--agent", "sales-ops"],
      "env": {
        "ODOO_URL": "https://erp.example.com", "ODOO_DB": "prod",
        "ODOO_USER": "ai-gateway", "ODOO_API_KEY": "<api key of a least-privilege user>",
        "EAG_APPROVAL_SECRET": "<32+ random chars>"
      }
    }
  }
}
```

4. When the agent proposes a change, a human reviews it and approves it:

```bash
erp-agent-guard pending --policy policy.yaml
erp-agent-guard approve p_1234abcd --policy policy.yaml    # shows the diff, asks y/N, prints a token
erp-agent-guard verify-audit audit.jsonl
```

### MCP tools

| tool | what it does |
|---|---|
| `erp_describe` | What this agent may read, write and create, and which fields are masked |
| `erp_search_read` | Search with an Odoo-style domain. Fields, filters and order are checked against the policy, and the output is masked |
| `erp_propose_write` | Dry-run an update and return a diff and a proposal id |
| `erp_propose_create` | Dry-run a creation |
| `erp_commit` | Apply a proposal, with the approval token when one is required |

The server speaks MCP over stdio (newline-delimited JSON-RPC 2.0: `initialize`, `ping`, `tools/list`, `tools/call`). It uses only the standard library, with no SDK dependency. An optional transport built on the official `mcp` SDK is on the roadmap.

## Demo

`python examples/demo.py` starts a fake Odoo with synthetic data and runs the real `serve` command as a subprocess. It then plays an agent over stdio. Here is the output, trimmed:

```text
>>> erp_search_read {"model": "res.partner", "domain": [["country_code", "=", "EC"]], "fields": ["name", "phone", "vat"]}
{ "count": 2, "records": [
  {"id": 1, "name": "Andes Hardware S.A.", "phone": "+593 2 555 0101", "vat": "***2001"},
  {"id": 2, "name": "Lucia Paredes",       "phone": "+593 99 555 0199", "vat": "***5678"} ] }

>>> erp_search_read {"model": "res.partner", "domain": [["vat", "=like", "17%"]]}
ERROR {"error": "policy_denied", "message": "domain: field 'vat' is masked and cannot be used as a filter"}

>>> erp_search_read {"model": "ir.config_parameter"}
ERROR {"error": "policy_denied", "message": "model 'ir.config_parameter' is on the deny list"}

>>> erp_propose_write {"model": "res.partner", "ids": [1], "values": {"credit_limit": 999999}}
ERROR {"error": "policy_denied", "message": "write: fields not allowed: ['credit_limit']"}

>>> erp_propose_write {"model": "res.partner", "ids": [2], "values": {"phone": "+593 99 555 0000"}}
{ "proposal_id": "p_a89781a6033c417a", "op": "write",
  "diff": [{"id": 2, "changes": {"phone": {"from": "+593 99 555 0199", "to": "+593 99 555 0000"}}}],
  "digest": "f0121bef...d695406", "approval_required": true,
  "next": "ask a human to run: erp-agent-guard approve p_a89781a6033c417a, then call erp_commit with the token" }

>>> erp_commit {"proposal_id": "p_a89781a6033c417a"}
ERROR {"error": "approval_invalid", "message": "this write needs a human approval token"}

$ erp-agent-guard approve p_a89781a6033c417a --policy policy.yaml --yes
proposal p_a89781a6033c417a  agent=sales-ops  write res.partner  status=pending
created 2026-11-14 00:28:18, expires 00:43:18
  record 2:
    phone: "+593 99 555 0199" -> "+593 99 555 0000"
p_a89781a6033c417a.1794634997.bf0a94cb61681e608cb72729ceb24c5781f2a0d4df6c9e2d3626131d05d6ab0e

>>> erp_commit {"proposal_id": "p_a89781a6033c417a", "approval_token": "p_a89781a6033c417a.1794634997.bf0a94cb..."}
{"proposal_id": "p_a89781a6033c417a", "status": "committed", "written": [2]}

$ erp-agent-guard verify-audit audit.jsonl
OK: 8 entries, chain intact, head=e1a0422e5a42fdd6
```

Audit lines look like this (one JSON object per line, chained by `prev` and `hash`):

```json
{"agent": "sales-ops", "approved": true, "digest": "f0121bef...", "event": "commit", "hash": "e1a0422e...", "model": "res.partner", "op": "write", "prev": "6fcd5e40...", "proposal": "p_a89781a6033c417a", "ts": 1794634099.001, "written": [2]}
```

## Tests

```bash
pip install -e ".[dev]"
pytest -q        # 76 tests, about 4 s
```

The tests run against `erp_agent_guard.fake_odoo`, an in-memory imitation of Odoo's `/jsonrpc` endpoint with synthetic data. No real Odoo or credentials are needed. They cover:

- policy validation
- every masking strategy
- domain-oracle and path-traversal refusals
- the dry-run, approve and commit flow
- token forgery, replay, expiry and cross-proposal reuse
- stale writes and a tampered proposal file
- quotas
- audit-chain tampering, including two processes writing one log
- a full MCP session over stdio with a real subprocess

To try the gateway by hand, run `erp-agent-guard fake-odoo --port 8069`.

## Threat model (short)

**What the gateway defends against:**
- an agent that is confused or prompt-injected and tries to read more than it should: hidden fields, PII, secrets models, or bulk dumps (limits are capped)
- writes to fields or models it should not touch
- writing without a human seeing the diff
- replaying or reusing an approval
- writing over a change someone made after the dry-run
- quietly editing the audit trail

**What it does not do:**
- It does not protect against someone with shell access to the gateway host. They can read the approval secret and the ERP key.
- It does not make the audit log tamper-proof. The log is tamper-evident: ship it to WORM storage or a SIEM.
- It does not check business logic inside the ERP. A permitted write can still trigger server-side automations.
- It does not replace Odoo ACLs and record rules. The gateway is the second layer.

## Why this exists / prior art

There are many Odoo MCP servers. Most expose the full ORM (`execute_kw`) to the model. Their write protection is usually a global on/off flag, or the protections are spread across a large feature set. The closest projects:

- **[odoo-mcp-gateway](https://github.com/parth-unjiya/odoo-mcp-gateway)** (Python, MIT) is a security-first Odoo MCP server. It has YAML model and field restrictions, RBAC, rate limiting, audit logging and a `dry_run` flag, plus far more tools than this project.
  - It is Odoo-only, and the agent logs in through a tool call with Odoo credentials.
  - If you want a feature-rich Odoo MCP server with security settings, use it.
- **[odoo-mcp / ERPipe](https://github.com/erpipe-org/mcp-odoo)** (Python, MIT) is a popular Odoo MCP server. It gates writes with an environment variable and approval tokens, and also exists as a hosted product.
  - I have not checked whether its tokens are bound to the content of the diff.
- **[erp-agent-guardrails](https://github.com/matheushpr94/erp-agent-guardrails)** (TypeScript) uses the same "propose, then confirm" pattern for a Brazilian financial ERP. Its confirmation is gated by chat channel and role.
- **Generic MCP gateways** such as Obot MCP Gateway, evav-gateway and keyless-agents (for Microsoft 365) apply policy at the level of *tool calls*. They do not know about ERP models, fields, domains or record diffs.
- **Odoo's own access rights** (`ir.model.access`, `ir.rule`, field `groups`) are the first layer. Keep using them. They do not give you diff review, approval bound to content, per-agent quotas or masking of fields the agent may read.

**What erp-agent-guard does differently:**
- The core is ERP-agnostic. Policy, diff, approval and audit sit on an adapter interface, so the same policy model will cover NetSuite.
- The approval token is cryptographically bound to the exact diff (proposal digest), carries an expiry, and the stale check runs again at commit.
- It treats domains and ordering as a **data-exfiltration channel**: no filtering or sorting on hidden or masked fields, and no dotted paths.
- The audit log is hash-chained, and a verifier command is included.
- The agent identity is fixed by the process. It is not something the model can say.
- It is small enough to audit: about 1,000 lines, standard library plus PyYAML.

## Resumen en español

`erp-agent-guard` es una pasarela de políticas entre agentes de IA (clientes MCP) y un ERP. Odoo vía JSON-RPC es el primer adaptador, y NetSuite está planificado.

Una política YAML define qué hace cada agente:
- qué modelos y campos puede leer
- qué puede escribir; por defecto todo es solo lectura
- qué campos con datos personales se enmascaran
- cuántas llamadas y escrituras puede hacer

Toda escritura es un *dry-run* que devuelve un diff, y se aplica solo con un token de aprobación humana firmado con HMAC sobre ese diff exacto. Si el registro cambió entre el *dry-run* y el commit, la escritura se rechaza. Todo queda en un log de auditoría JSONL encadenado por hashes, que se verifica con `erp-agent-guard verify-audit`.

Los tests usan un Odoo falso en memoria con datos sintéticos (`pytest -q`). Úsalo solo con tus propios sistemas o con los que estés autorizado a administrar.

## License

Apache-2.0. See [LICENSE](LICENSE).
