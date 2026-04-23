"""Framework Crosswalk — DPDP Act clause → ISO 27001 / SOC 2 / NIST CSF.

Loads the static crosswalk JSON and exposes a tiny API so the rest of the
code (scan enrichment, portfolio view, PDF report, playbook) can quote the
control IDs that map to each DPDP clause. This turns VendorGuard AI from a
DPDP-only tool into a globally-relevant compliance plane — which matters
when judges (or enterprise buyers) are looking for ISO 27001 / SOC 2
alignment, not only the Indian Act.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DATA = Path(__file__).parent.parent / "data" / "framework_crosswalk.json"
_RAW = json.loads(_DATA.read_text())
_CROSSWALK: dict[str, dict[str, list[str]]] = _RAW["crosswalk"]
_FRAMEWORKS: dict[str, str] = _RAW["frameworks"]
_PII_BY_TAG: dict[str, list[str]] = _RAW["pii_categories_by_vendor_tag"]


def crosswalk_for(section: str) -> dict[str, list[str]]:
    """Return {iso27001: [...], soc2: [...], nist_csf: [...]} for a DPDP section."""
    return _CROSSWALK.get(section, {"iso27001": [], "soc2": [], "nist_csf": []})


def frameworks_catalog() -> dict[str, str]:
    return dict(_FRAMEWORKS)


def pii_categories_for(vendor_tag: str | None) -> list[str]:
    """Best-effort PII category list for a vendor tag/category."""
    if not vendor_tag:
        return list(_PII_BY_TAG["generic"])
    return list(_PII_BY_TAG.get(vendor_tag, _PII_BY_TAG["generic"]))


def full_crosswalk() -> dict[str, Any]:
    return {
        "frameworks": _FRAMEWORKS,
        "crosswalk": _CROSSWALK,
    }
