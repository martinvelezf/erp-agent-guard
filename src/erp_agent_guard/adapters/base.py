"""Adapter interface. The guard only ever talks to an ERP through this."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ERPAdapter(Protocol):
    name: str

    def search_read(self, model: str, domain: list, fields: list[str], limit: int, offset: int = 0,
                    order: str | None = None) -> list[dict[str, Any]]: ...

    def read(self, model: str, ids: list[int], fields: list[str]) -> list[dict[str, Any]]: ...

    def write(self, model: str, ids: list[int], values: dict[str, Any]) -> bool: ...

    def create(self, model: str, values: dict[str, Any]) -> int: ...
