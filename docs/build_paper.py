#!/usr/bin/env python3
"""Build the AgentGuard technical brief (A4 PDF).

Content lives in ``docs/paper.json`` (heading / paragraph / table / pagebreak
elements); the typography is here so the document is dense enough to read like a
brief rather than a slide dump:

* A4, 0.82 in side margins, 10 pt body on 13.6 pt leading, justified
* section headings in the accent colour, no numbering games
* tables at 8 pt with a filled header row and zebra striping
* "Page N of M" footer, computed in a second pass

Usage:
    python docs/build_paper.py docs/paper.json docs/AgentGuard-brief.pdf
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

ACCENT = colors.HexColor("#0E7490")
INK = colors.HexColor("#0F172A")
MUTED = colors.HexColor("#64748B")
RULE = colors.HexColor("#E2E8F0")
ZEBRA = colors.HexColor("#F8FAFC")
HEADER_BG = colors.HexColor("#0E7490")

MARGIN_X = 0.82 * inch
MARGIN_TOP = 0.72 * inch
MARGIN_BOTTOM = 0.72 * inch

STYLES = {
    "h1": ParagraphStyle(
        "h1", fontName="Helvetica-Bold", fontSize=16.5, leading=20,
        textColor=INK, spaceAfter=8, alignment=TA_LEFT,
    ),
    "h2": ParagraphStyle(
        "h2", fontName="Helvetica-Bold", fontSize=11.8, leading=15,
        textColor=ACCENT, spaceBefore=13, spaceAfter=5, alignment=TA_LEFT,
    ),
    "h3": ParagraphStyle(
        "h3", fontName="Helvetica-Bold", fontSize=10.2, leading=13.5,
        textColor=INK, spaceBefore=9, spaceAfter=3, alignment=TA_LEFT,
    ),
    "body": ParagraphStyle(
        "body", fontName="Helvetica", fontSize=10, leading=13.6,
        textColor=INK, spaceAfter=6, alignment=TA_JUSTIFY,
    ),
    "cell": ParagraphStyle(
        "cell", fontName="Helvetica", fontSize=7.9, leading=10.2, textColor=INK,
    ),
    "cell_head": ParagraphStyle(
        "cell_head", fontName="Helvetica-Bold", fontSize=7.9, leading=10.2, textColor=colors.white,
    ),
}


def build_table(rows: list[list[str]], widths: list[float] | None, available: float) -> Table:
    head = [Paragraph(str(cell), STYLES["cell_head"]) for cell in rows[0]]
    body = [[Paragraph(str(cell), STYLES["cell"]) for cell in row] for row in rows[1:]]
    ratios = widths or [1.0] * len(rows[0])
    total = sum(ratios)
    col_widths = [available * float(ratio) / total for ratio in ratios]

    table = Table([head, *body], colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.2),
        ("LEFTPADDING", (0, 0), (-1, -1), 4.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4.5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.35, RULE),
        ("LINEBEFORE", (0, 0), (-1, -1), 0, colors.white),
    ]
    for index in range(1, len(rows)):
        if index % 2 == 0:
            style.append(("BACKGROUND", (0, index), (-1, index), ZEBRA))
    table.setStyle(TableStyle(style))
    return table


class NumberedCanvas(pdfcanvas.Canvas):
    """Adds 'Page N of M' once the page count is known."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self._footer(total)
            super().showPage()
        super().save()

    def _footer(self, total: int):
        self.saveState()
        self.setStrokeColor(RULE)
        self.setLineWidth(0.4)
        self.line(MARGIN_X, 0.58 * inch, A4[0] - MARGIN_X, 0.58 * inch)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(MUTED)
        self.drawString(MARGIN_X, 0.44 * inch, "AgentGuard - technical brief")
        self.drawRightString(A4[0] - MARGIN_X, 0.44 * inch, f"Page {self._pageNumber} of {total}")
        self.restoreState()


def build(spec: dict, out_path: Path) -> int:
    document = BaseDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=MARGIN_X,
        rightMargin=MARGIN_X,
        topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOTTOM,
        title=spec.get("title", ""),
        author=spec.get("author", ""),
        subject=spec.get("subject", "Technical brief"),
    )
    frame = Frame(
        document.leftMargin, document.bottomMargin,
        document.width, document.height,
        id="body", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
    )
    document.addPageTemplates([PageTemplate(id="page", frames=[frame])])

    available = document.width
    story = []
    heading_levels = {1: "h1", 2: "h2", 3: "h3"}
    tables = 0

    for element in spec.get("elements", []):
        kind = element.get("type")
        if kind == "heading":
            level = int(element.get("level", 1))
            story.append(Paragraph(element.get("text", ""), STYLES[heading_levels.get(level, "h2")]))
        elif kind == "paragraph":
            story.append(Paragraph(element.get("text", ""), STYLES["body"]))
        elif kind == "table":
            rows = element.get("rows") or []
            if not rows:
                continue
            tables += 1
            story.append(KeepTogether([build_table(rows, element.get("widths"), available)]))
            story.append(Spacer(1, 9))
        elif kind == "pagebreak":
            story.append(PageBreak())

    document.build(story, canvasmaker=NumberedCanvas)
    return tables


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    spec = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    tables = build(spec, Path(argv[2]))
    print(json.dumps({"ok": True, "output": argv[2], "tables": tables}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
