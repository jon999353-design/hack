"""End-to-end demo driver — run this live on stage.

What this shows in ~60 seconds:
  1. Scans a vendor    → trust score + DPDP exposure printed to terminal
  2. Activates gateway → token + scope shown
  3. Simulates bulk export → blocked, token revoked, WhatsApp alert fired
  4. Prints 'CONTAINED IN 3.x SECONDS' as the mic-drop line

Usage:
  # in one terminal
  uvicorn app.main:app --host 127.0.0.1 --port 8765
  # in another
  python scripts/demo_attack.py
"""
from __future__ import annotations

import sys
import time

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

API = "http://127.0.0.1:8765"
VENDOR = "paytrust-partner.com"
console = Console()


def _inr(n: int) -> str:
    if n >= 1_00_00_000:
        return f"₹{n/1e7:.0f} Cr"
    if n >= 1_00_000:
        return f"₹{n/1e5:.0f} L"
    return f"₹{n:,}"


def step(title: str) -> None:
    console.rule(f"[bold amber]{title}")


def banner() -> None:
    console.print(
        Panel.fit(
            "[bold yellow]VendorGuard AI[/] — Vendor Access Control Plane\n"
            "[dim]The only vendor risk scanner that speaks DPDP.[/]",
            border_style="yellow",
        )
    )


def scan(vendor: str) -> dict:
    step(f"1  Scan: {vendor}")
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}")
    ) as p:
        t = p.add_task("Parallel OSINT calls: Shodan · HIBP · crt.sh · VirusTotal · DNS · TLS …", total=None)
        r = httpx.post(f"{API}/scan", json={"vendor": vendor}, timeout=45.0)
        p.remove_task(t)
    r.raise_for_status()
    data = r.json()

    tbl = Table(title=f"Findings for {vendor}", show_edge=False, header_style="bold")
    tbl.add_column("Source", style="cyan")
    tbl.add_column("Finding", style="white")
    tbl.add_column("Severity", justify="right")
    for f in data["findings"]:
        tbl.add_row(f["source"], f["title"], f["severity"].upper())
    console.print(tbl)

    console.print(
        Panel.fit(
            f"Trust Score: [bold {data['trust']['color']}]{data['trust']['score']}/100[/]  "
            f"→ [bold]{data['trust']['label']}[/]\n"
            f"DPDP Exposure: [bold red]{_inr(data['total_dpdp_exposure_inr'])}[/]\n"
            f"\n[italic dim]{data['ai_summary']}[/]",
            title="Board-ready summary",
            border_style=data["trust"]["color"],
        )
    )
    return data


def activate(vendor: str) -> dict:
    step("2  Activate Gateway")
    r = httpx.post(
        f"{API}/gateway/activate",
        json={"vendor": vendor, "scope": ["reporting"], "max_records_per_request": 500},
        timeout=10.0,
    )
    r.raise_for_status()
    s = r.json()
    console.print(
        f"[green]● ACTIVE[/]  token=[yellow]{s['token_id']}[/]  "
        f"scope={s['scope']}  limit={s['max_records_per_request']} records/request"
    )
    return s


def simulate(vendor: str) -> dict:
    step("3  Live Attack Simulation")
    console.print(
        "[dim]Vendor just requested 12,000 customer records on /reporting/export "
        "(baseline: ≤500/month).[/]\n"
    )
    time.sleep(0.5)
    t0 = time.perf_counter()
    r = httpx.post(
        f"{API}/gateway/proxy",
        json={
            "vendor": vendor,
            "endpoint": "reporting/export",
            "records_requested": 12_000,
            "client_ip": "203.0.113.42",
        },
        timeout=30.0,
    )
    r.raise_for_status()
    wall = time.perf_counter() - t0
    out = r.json()
    ev = out["event"]
    console.print(
        Panel(
            f"[bold red]{ev['title']}[/]\n\n"
            f"{ev['summary']}\n\n"
            f"{ev['action_taken']}\n\n"
            f"DPDP exposure avoided: [bold red]{_inr(ev['dpdp_exposure_inr'])}[/]",
            border_style="red",
            title="🚨  CRITICAL ALERT",
        )
    )
    console.print(
        Panel.fit(
            f"[bold green]Contained in {ev['containment_seconds']}s[/]  "
            f"(end-to-end wall time: {wall*1000:.0f}ms)",
            border_style="green",
        )
    )
    return out


def closing(scan_data: dict, sim_out: dict) -> None:
    step("4  Mic drop")
    ev = sim_out["event"]
    console.print(
        Panel.fit(
            f"Before VendorGuard: breach in [bold red]weeks[/], ₹18 Cr average loss, ₹250 Cr DPDP fine.\n"
            f"After VendorGuard: breach contained in [bold green]{ev['containment_seconds']} seconds[/], "
            f"{_inr(ev['dpdp_exposure_inr'])} exposure [bold]avoided[/], audit trail preserved.\n\n"
            f"[bold yellow]Teleport controls access. StrongDM controls queries.\n"
            f"VendorGuard controls API-level behaviour — and maps every action to DPDP penalty in ₹.[/]",
            border_style="yellow",
        )
    )


def main() -> int:
    banner()
    vendor = sys.argv[1] if len(sys.argv) > 1 else VENDOR
    try:
        httpx.get(f"{API}/health", timeout=3.0).raise_for_status()
    except Exception:
        console.print(f"[red]Backend not reachable at {API}. Start it with:[/] uvicorn app.main:app --host 127.0.0.1 --port 8765")
        return 2
    scan_data = scan(vendor)
    activate(vendor)
    sim_out = simulate(vendor)
    closing(scan_data, sim_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
