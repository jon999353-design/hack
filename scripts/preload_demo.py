"""Pre-warm the backend before a live demo.

Runs a full scan against every bundled demo vendor so:
  * SQLite has cached /scan responses → /scan/{vendor} is instant
  * /graph has all vendors populated
  * the first judge question never triggers a cold start

Usage:
  python scripts/preload_demo.py                              # default: http://127.0.0.1:8765
  python scripts/preload_demo.py https://vendorguard-api...   # against a deployed backend
"""
from __future__ import annotations

import sys
import time

import httpx

DEFAULT_API = "http://127.0.0.1:8765"
VENDORS = [
    "paytrust-partner.com",
    "shopquick-vendor.com",
    "healthbuddy-partner.com",
    "databridge-cloud.com",
]


def _inr(n: int) -> str:
    if n >= 10_000_000:
        return f"₹{n/1e7:.0f} Cr"
    if n >= 100_000:
        return f"₹{n/1e5:.0f} L"
    return f"₹{n:,}"


def main() -> int:
    api = (sys.argv[1] if len(sys.argv) > 1 else DEFAULT_API).rstrip("/")
    print(f"Preloading VendorGuard demo data on: {api}\n")

    # Health
    try:
        r = httpx.get(f"{api}/health", timeout=10.0)
        r.raise_for_status()
    except Exception as exc:
        print(f"[!] Backend not reachable at {api} — {exc}")
        return 1
    print(f"[ok] backend healthy")

    for v in VENDORS:
        t0 = time.perf_counter()
        try:
            r = httpx.post(f"{api}/scan", json={"vendor": v}, timeout=60.0)
            r.raise_for_status()
            data = r.json()
            dt = (time.perf_counter() - t0) * 1000
            print(
                f"[ok] {v:<28} score={data['trust']['score']:>3}/100 "
                f"({data['trust']['band']:>5})  exposure={_inr(data['total_dpdp_exposure_inr']):<8}  "
                f"findings={len(data['findings']):>2}  {dt:>5.0f}ms"
            )
        except Exception as exc:
            print(f"[!] {v}: scan failed — {exc}")

    # Activate gateway on the headline demo vendor so the "Simulate Attack"
    # button works instantly with zero extra clicks on stage.
    try:
        httpx.post(
            f"{api}/gateway/activate",
            json={"vendor": VENDORS[0], "scope": ["reporting"], "max_records_per_request": 500},
            timeout=10.0,
        ).raise_for_status()
        httpx.post(f"{api}/gateway/reset/{VENDORS[0]}", timeout=10.0).raise_for_status()
        print(f"[ok] gateway activated + reset on {VENDORS[0]}")
    except Exception as exc:
        print(f"[!] gateway activation failed: {exc}")

    # Sanity-check the graph has all vendors now
    try:
        g = httpx.get(f"{api}/graph", timeout=10.0).json()
        print(f"[ok] graph: {len(g['nodes'])} nodes, {len(g['edges'])} edges")
    except Exception as exc:
        print(f"[!] /graph failed: {exc}")

    print("\nDemo is warm. Open the dashboard and click Scan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
