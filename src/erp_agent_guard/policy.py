"""Policy model: which agent may touch which ERP model and field, and how.

The policy is a YAML file. Everything not explicitly allowed is denied:
unknown agents, unknown models, unlisted fields, and writes unless the
agent (or model) is switched to ``read-write``.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import PolicyError

MODES = ("read-only", "read-write")
MASK_STRATEGIES = ("redact", "email", "last4", "hash", "initials")

# Models no agent should ever reach through this gateway, whatever the YAML
# says: secrets, access control, scheduled code, module management.
BUILTIN_DENY_MODELS = (
    "ir.config_parameter",
    "ir.cron",
    "ir.rule",
    "ir.model.access",
    "ir.module.module",
    "ir.actions.server",
    "ir.mail_server",
    "res.users.apikeys",
    "res.users.apikeys.description",
    "auth_totp.device",
    "base.module.*",
)

# Field names that are denied on every model.
BUILTIN_DENY_FIELDS = (
    "password",
    "new_password",
    "api_key",
    "api_key_ids",
    "totp_secret",
    "signature",
    "oauth_access_token",
)


@dataclass(frozen=True)
class ModelRule:
    name: str
    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()
    create: tuple[str, ...] = ()
    mask: dict[str, str] = field(default_factory=dict)
    mode: str | None = None  # overrides the agent mode for this model
    max_records: int | None = None


@dataclass(frozen=True)
class Quota:
    calls_per_minute: int = 60
    writes_per_day: int = 50


@dataclass(frozen=True)
class AgentRule:
    name: str
    mode: str
    models: dict[str, ModelRule]
    quota: Quota
    max_records: int


@dataclass(frozen=True)
class ApprovalConfig:
    required: bool = True
    secret_env: str = "EAG_APPROVAL_SECRET"
    ttl_seconds: int = 900


@dataclass(frozen=True)
class Policy:
    agents: dict[str, AgentRule]
    deny_models: tuple[str, ...]
    deny_fields: tuple[str, ...]
    approval: ApprovalConfig
    audit_path: str | None
    proposals_path: str | None
    mask_salt_env: str = "EAG_MASK_SALT"

    # ---- lookups -------------------------------------------------------
    def agent(self, name: str) -> AgentRule:
        try:
            return self.agents[name]
        except KeyError:
            raise PolicyError(f"agent '{name}' is not declared in the policy") from None

    def is_model_denied(self, model: str) -> bool:
        return any(fnmatch.fnmatchcase(model, pat) for pat in self.deny_models)

    def is_field_denied(self, fname: str) -> bool:
        return any(fnmatch.fnmatchcase(fname, pat) for pat in self.deny_fields)

    def model_rule(self, agent: str, model: str) -> ModelRule:
        a = self.agent(agent)
        if self.is_model_denied(model):
            raise PolicyError(f"model '{model}' is on the deny list")
        rule = a.models.get(model)
        if rule is None:
            raise PolicyError(f"model '{model}' is not allowed for agent '{agent}'")
        return rule

    def effective_mode(self, agent: str, model: str) -> str:
        a = self.agent(agent)
        rule = self.model_rule(agent, model)
        # A model can only be *more* restrictive than the agent, never less.
        if a.mode == "read-only":
            return "read-only"
        return rule.mode or a.mode

    def readable_fields(self, agent: str, model: str) -> tuple[str, ...]:
        rule = self.model_rule(agent, model)
        return tuple(f for f in rule.read if not self.is_field_denied(f))

    def writable_fields(self, agent: str, model: str) -> tuple[str, ...]:
        rule = self.model_rule(agent, model)
        return tuple(f for f in rule.write if not self.is_field_denied(f))

    def creatable_fields(self, agent: str, model: str) -> tuple[str, ...]:
        rule = self.model_rule(agent, model)
        return tuple(f for f in rule.create if not self.is_field_denied(f))

    def max_records(self, agent: str, model: str) -> int:
        rule = self.model_rule(agent, model)
        return rule.max_records or self.agent(agent).max_records


# ---- loading ---------------------------------------------------------------

def _str_list(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where}: expected a list of strings")
    return tuple(value)


def _mode(value: Any, where: str, default: str | None) -> str | None:
    if value is None:
        return default
    if value not in MODES:
        raise PolicyError(f"{where}: mode must be one of {MODES}, got {value!r}")
    return value


def _positive_int(value: Any, where: str, default: int | None) -> int | None:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PolicyError(f"{where}: expected a positive integer, got {value!r}")
    return value


def _check_keys(d: dict, allowed: set[str], where: str) -> None:
    unknown = set(d) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {sorted(unknown)}")


def load_policy_dict(data: Any) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy: top level must be a mapping")
    _check_keys(data, {"version", "defaults", "agents", "deny", "approval", "audit", "proposals", "masking"}, "policy")
    if data.get("version", 1) != 1:
        raise PolicyError("policy: only version 1 is supported")

    defaults = data.get("defaults") or {}
    _check_keys(defaults, {"mode", "max_records", "quota"}, "defaults")
    default_mode = _mode(defaults.get("mode"), "defaults", "read-only")
    default_max = _positive_int(defaults.get("max_records"), "defaults.max_records", 80)
    dq = defaults.get("quota") or {}
    _check_keys(dq, {"calls_per_minute", "writes_per_day"}, "defaults.quota")
    default_quota = Quota(
        calls_per_minute=_positive_int(dq.get("calls_per_minute"), "defaults.quota", 60),
        writes_per_day=_positive_int(dq.get("writes_per_day"), "defaults.quota", 50),
    )

    deny = data.get("deny") or {}
    _check_keys(deny, {"models", "fields"}, "deny")
    deny_models = BUILTIN_DENY_MODELS + _str_list(deny.get("models"), "deny.models")
    deny_fields = BUILTIN_DENY_FIELDS + _str_list(deny.get("fields"), "deny.fields")

    agents_raw = data.get("agents")
    if not isinstance(agents_raw, dict) or not agents_raw:
        raise PolicyError("policy: 'agents' must be a non-empty mapping")

    agents: dict[str, AgentRule] = {}
    for aname, araw in agents_raw.items():
        where = f"agents.{aname}"
        araw = araw or {}
        if not isinstance(araw, dict):
            raise PolicyError(f"{where}: expected a mapping")
        _check_keys(araw, {"mode", "max_records", "quota", "models"}, where)
        amode = _mode(araw.get("mode"), where, default_mode)
        q = araw.get("quota") or {}
        _check_keys(q, {"calls_per_minute", "writes_per_day"}, f"{where}.quota")
        quota = Quota(
            calls_per_minute=_positive_int(q.get("calls_per_minute"), f"{where}.quota", default_quota.calls_per_minute),
            writes_per_day=_positive_int(q.get("writes_per_day"), f"{where}.quota", default_quota.writes_per_day),
        )
        models_raw = araw.get("models") or {}
        if not isinstance(models_raw, dict):
            raise PolicyError(f"{where}.models: expected a mapping")
        models: dict[str, ModelRule] = {}
        for mname, mraw in models_raw.items():
            mwhere = f"{where}.models.{mname}"
            mraw = mraw or {}
            if not isinstance(mraw, dict):
                raise PolicyError(f"{mwhere}: expected a mapping")
            _check_keys(mraw, {"read", "write", "create", "mask", "mode", "max_records"}, mwhere)
            if any(fnmatch.fnmatchcase(mname, p) for p in deny_models):
                raise PolicyError(f"{mwhere}: model is on the deny list and cannot be allowed")
            read = _str_list(mraw.get("read"), f"{mwhere}.read")
            write = _str_list(mraw.get("write"), f"{mwhere}.write")
            create = _str_list(mraw.get("create"), f"{mwhere}.create")
            for f in read + write + create:
                if any(fnmatch.fnmatchcase(f, p) for p in deny_fields):
                    raise PolicyError(f"{mwhere}: field '{f}' is on the deny list")
            # Writing a field you cannot read would make the diff unreviewable.
            missing = [f for f in write if f not in read]
            if missing:
                raise PolicyError(f"{mwhere}: writable fields must also be readable: {missing}")
            mask = mraw.get("mask") or {}
            if not isinstance(mask, dict):
                raise PolicyError(f"{mwhere}.mask: expected a mapping field -> strategy")
            for f, strat in mask.items():
                if strat not in MASK_STRATEGIES:
                    raise PolicyError(f"{mwhere}.mask.{f}: unknown strategy {strat!r}; use one of {MASK_STRATEGIES}")
                if f in write:
                    raise PolicyError(f"{mwhere}.mask.{f}: a masked field cannot be writable (the agent cannot see what it overwrites)")
            models[mname] = ModelRule(
                name=mname,
                read=read,
                write=write,
                create=create,
                mask=dict(mask),
                mode=_mode(mraw.get("mode"), mwhere, None),
                max_records=_positive_int(mraw.get("max_records"), f"{mwhere}.max_records", None),
            )
        agents[str(aname)] = AgentRule(
            name=str(aname),
            mode=amode,
            models=models,
            quota=quota,
            max_records=_positive_int(araw.get("max_records"), f"{where}.max_records", default_max),
        )

    appr = data.get("approval") or {}
    _check_keys(appr, {"required", "secret_env", "ttl_seconds"}, "approval")
    required = appr.get("required", True)
    if not isinstance(required, bool):
        raise PolicyError("approval.required: expected true/false")
    approval = ApprovalConfig(
        required=required,
        secret_env=str(appr.get("secret_env", "EAG_APPROVAL_SECRET")),
        ttl_seconds=_positive_int(appr.get("ttl_seconds"), "approval.ttl_seconds", 900),
    )

    audit = data.get("audit") or {}
    _check_keys(audit, {"path"}, "audit")
    proposals = data.get("proposals") or {}
    _check_keys(proposals, {"path"}, "proposals")
    masking = data.get("masking") or {}
    _check_keys(masking, {"salt_env"}, "masking")

    return Policy(
        agents=agents,
        deny_models=deny_models,
        deny_fields=deny_fields,
        approval=approval,
        audit_path=audit.get("path"),
        proposals_path=proposals.get("path"),
        mask_salt_env=str(masking.get("salt_env", "EAG_MASK_SALT")),
    )


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: invalid YAML: {exc}") from exc
    policy = load_policy_dict(data)
    # Relative paths in the policy are relative to the policy file.
    base = path.parent
    def _rel(p: str | None) -> str | None:
        if p is None:
            return None
        pp = Path(p)
        return str(pp if pp.is_absolute() else (base / pp))
    return Policy(
        agents=policy.agents,
        deny_models=policy.deny_models,
        deny_fields=policy.deny_fields,
        approval=policy.approval,
        audit_path=_rel(policy.audit_path),
        proposals_path=_rel(policy.proposals_path),
        mask_salt_env=policy.mask_salt_env,
    )
