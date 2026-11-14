# Roadmap

v0.1 is the MVP: Odoo JSON-RPC, stdio MCP, YAML policy, dry-run + approval, masking, quotas, audit.

## v0.2
- **NetSuite adapter**: SuiteQL for reads (policy allowlist becomes the SELECT list), REST Record API for writes, OAuth 2.0 M2M with certificate. Model names map to record types.
- **Odoo JSON-2 API** (`/json/2/<model>/<method>`, Odoo 19+) adapter, since XML-RPC/JSON-RPC are scheduled for removal in a future Odoo series.
- **Optional official `mcp` SDK transport** (`pip install erp-agent-guard[sdk]`) for Streamable HTTP with OAuth, keeping the stdlib stdio server as the default.
- **MCP elicitation** for approvals where the client supports it (the human approves inside the chat UI), keeping the HMAC token as the fallback.
- **Approval out of band**: post the diff to a webhook (Slack/Teams/email) with approve/deny links instead of the CLI.
- **Per-field value rules**: ranges and enums (`credit_limit <= 10000`, `state in [draft, sent]`), regex for formats (e.g. Ecuador RUC/cédula check digits).
- **Row-level scoping** in the policy: a mandatory domain appended to every read/write (`company_id = 1`, `user_id = <bound user>`).
- **Shared quota state** (SQLite/Redis) so several gateway processes enforce one budget.
- **Audit sinks**: syslog/OTLP export, periodic signed checkpoints of the chain head.

## Later
- Many2many/one2many writes with an expanded diff (show which links are added/removed).
- `unlink` behind a separate, stricter approval tier.
- Policy unit tests (`erp-agent-guard test-policy cases.yaml`) to assert "agent X cannot read field Y" in CI.
- Windows support for the audit file lock (currently `fcntl`).
