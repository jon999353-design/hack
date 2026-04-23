"""CERT-In 6-hour Incident Report generator.

Takes a persisted `AlertEvent` and renders a pre-filled CERT-In incident
report (Form A equivalent) as a board-ready PDF. This makes VendorGuard AI
the only vendor-risk tool that also discharges the regulator-facing paperwork
triggered by §8(6) DPDP + CERT-In directions, 28 Apr 2022.
"""
from __future__ import annotations

import io
import time
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _rupees(inr: int) -> str:
    if inr >= 10_000_000:
        return f"Rs {inr / 1e7:.1f} Cr"
    if inr >= 100_000:
        return f"Rs {inr / 1e5:.1f} L"
    return f"Rs {inr:,}"


def render_pdf(alert: dict[str, Any], scan: dict[str, Any] | None) -> bytes:
    """Return a PDF bytes blob of a CERT-In/DPB-ready incident report."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"CERT-In incident report — {alert.get('vendor','')}",
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=16, spaceAfter=6)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12, spaceAfter=4)
    small = ParagraphStyle("small", parent=styles["BodyText"], fontSize=9)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=10, spaceAfter=4)

    story = []
    story.append(Paragraph("CERT-In / DPB Incident Intimation", h1))
    story.append(Paragraph(
        f"Reference: <b>{alert.get('id','')}</b> &nbsp;·&nbsp; Generated: "
        f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        small,
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Pursuant to the CERT-In Directions dated 28 Apr 2022 requiring reporting of "
        "cyber incidents within six hours of notice, and §8(6) of the Digital Personal "
        "Data Protection Act 2023 requiring intimation of personal data breaches to the "
        "Data Protection Board and affected Data Principals, the reporting entity "
        "intimates the following incident.",
        body,
    ))
    story.append(Spacer(1, 6))

    incident_rows = [
        ["Field", "Value"],
        [
            "Reporting entity",
            (scan or {}).get("reported_by", "Rashi Innovators — Your Company"),
        ],
        ["Vendor / data processor", alert.get("vendor", "")],
        ["Incident detected at", alert.get("at", "")],
        ["Severity", (alert.get("severity") or "").upper()],
        [
            "Containment time",
            f"{alert.get('containment_seconds', 0)} seconds (wall-clock at gateway)",
        ],
        ["Estimated DPDP exposure", _rupees(int(alert.get("dpdp_exposure_inr") or 0))],
        ["Anomaly score (ML)", f"{alert.get('anomaly_score', 'n/a')}"],
    ]
    t = Table(incident_rows, colWidths=[55 * mm, 110 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f1f5f9")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Incident narrative (Form A §3)", h2))
    story.append(Paragraph(alert.get("title", ""), body))
    story.append(Paragraph(alert.get("summary", ""), body))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Containment actions already taken", h2))
    story.append(Paragraph(alert.get("action_taken", ""), body))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Technical indicators", h2))
    ioc_rows = [
        ["Indicator", "Value"],
        ["Source channel", "VendorGuard Access Gateway (IsolationForest ML + policy)"],
        ["Decision", "BLOCK (automated)"],
        ["Evidence artefact", f"alert:{alert.get('id','')}"],
    ]
    if scan:
        ioc_rows.append(["Trust score", str((scan.get("trust") or {}).get("score", ""))])
        ioc_rows.append(["Findings total", str(len(scan.get("findings") or []))])
    tt = Table(ioc_rows, colWidths=[55 * mm, 110 * mm])
    tt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(tt)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Regulatory mappings", h2))
    reg_rows = [
        ["Regulator / framework", "Obligation", "Status"],
        ["CERT-In Directions (28 Apr 2022)", "Report within 6 hours of notice", "Filed by this intimation"],
        ["DPDP Act 2023 §8(6)", "Notify Data Protection Board & affected principals", "Filed / scheduled"],
        ["DPDP Act 2023 §8(5)", "Implement reasonable security safeguards", "Gateway auto-enforced"],
        ["RBI / IRDAI / SEBI sector rules", "Sector-specific breach notification", "To be assessed"],
    ]
    trt = Table(reg_rows, colWidths=[60 * mm, 70 * mm, 35 * mm])
    trt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(trt)
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "This intimation is generated automatically by VendorGuard AI v3 from "
        "a live gateway enforcement event. Source of truth: alert id above.",
        small,
    ))
    doc.build(story)
    return buf.getvalue()
