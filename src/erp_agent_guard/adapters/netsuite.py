"""NetSuite adapter placeholder (planned for v0.2, see ROADMAP.md).

The intended mapping: ``search_read`` -> SuiteQL (``/query/v1/suiteql``)
with the policy's field allowlist as the SELECT list; ``read``/``write``/
``create`` -> REST Record API (``/record/v1/{type}/{id}``), auth via
OAuth 2.0 M2M (client credentials with certificate). Model names map to
record types (``customer``, ``salesorder``...).
"""

from __future__ import annotations


class NetSuiteRestAdapter:
    name = "netsuite"

    def __init__(self, *args, **kwargs):
        raise NotImplementedError("NetSuite adapter is not implemented yet (planned for v0.2)")
