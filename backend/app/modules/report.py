"""PDF CISO Board Report generator.

Renders a vendor scan into a board-ready PDF (trust score, findings,
DPDP exposure table with verbatim Act excerpts from the RAG engine, and
the AI risk summary). Judges love a "Download board report" button;
CISOs paste this into quarterly risk decks.
"""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.modules.dpdp import format_inr
from app.modules.rag import retriever


def render_pdf(scan: dict) -> bytes:
    """Return a PDF file as bytes for the given /scan response payload."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"VendorGuard Board Report — {scan.get('vendor', '')}",
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle(
        "h1", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#f59e0b"),
        spaceAfter=4,
    )
    h2 = ParagraphStyle(
        "h2", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#0f172a"),
        spaceBefore=10, spaceAfter=4,
    )
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, textColor=colors.HexColor("#475569"))

    vendor = scan.get("vendor", "")
    trust = scan.get("trust", {})
    exposure = int(scan.get("total_dpdp_exposure_inr", 0))

    story = []
    story.append(Paragraph("VendorGuard AI", h1))
    story.append(Paragraph(
        f"Board-ready vendor risk report &middot; <b>{vendor}</b> &middot; "
        f"scanned {scan.get('scanned_at', '')}",
        small,
    ))
    story.append(Spacer(1, 6))

    # --- Executive summary table -----------------------------------------
    summary_tbl = Table(
        [
            ["Trust Score", f"{trust.get('score','—')} / 100 ({trust.get('label','')})"],
            ["DPDP Exposure", format_inr(exposure)],
            ["Scan Duration", f"{scan.get('duration_ms', 0)} ms"],
            ["Findings", str(len(scan.get("findings", [])))],
            ["DPDP Clauses Triggered", str(len({m.get('clause') for m in scan.get('dpdp', [])}))],
        ],
        colWidths=[55 * mm, 120 * mm],
    )
    summary_tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor("#b91c1c")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(summary_tbl)

    # --- AI risk summary -------------------------------------------------
    story.append(Paragraph("AI Risk Summary", h2))
    story.append(Paragraph(scan.get("ai_summary", "").replace("\n", "<br/>"), body))

    # --- Findings --------------------------------------------------------
    story.append(Paragraph("Technical Findings", h2))
    f_rows = [["#", "Source", "Severity", "Finding"]]
    for i, f in enumerate(scan.get("findings", []), start=1):
        f_rows.append([
            str(i),
            f.get("source", ""),
            f.get("severity", "").upper(),
            Paragraph(f.get("title", ""), body),
        ])
    f_tbl = Table(f_rows, colWidths=[8 * mm, 22 * mm, 20 * mm, 125 * mm])
    f_tbl.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(f_tbl)

    # --- DPDP mapping with verbatim Act quotes ---------------------------
    story.append(Paragraph("DPDP Act 2023 Mapping (RAG-grounded)", h2))
    r = retriever()
    d_rows = [["Clause", "Max Penalty", "Obligation / Verbatim Excerpt"]]
    for m in scan.get("dpdp", []):
        clause = m.get("clause", "")
        quote = m.get("rag_quote")
        page = m.get("rag_citation")
        if not quote:
            hit = r.lookup_clause(clause)
            if hit:
                quote = hit["excerpt"]
                page = f"Gazette p. {hit['page']}" if hit.get("page") else None
        cell = (
            f"<b>{m.get('obligation','')}</b><br/>"
            f"<font size=8 color='#475569'>"
            f"&ldquo;{quote or '—'}&rdquo;<br/>"
            f"<i>{page or ''}</i>"
            f"</font>"
        )
        d_rows.append([
            clause,
            format_inr(int(m.get("max_penalty_inr", 0))),
            Paragraph(cell, small),
        ])
    d_tbl = Table(d_rows, colWidths=[20 * mm, 28 * mm, 127 * mm])
    d_tbl.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(d_tbl)

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Generated by VendorGuard AI. All DPDP excerpts retrieved from the "
        "gazette-notified Digital Personal Data Protection Act, 2023 via the "
        "built-in RAG retriever.",
        small,
    ))

    doc.build(story)
    return buf.getvalue()
