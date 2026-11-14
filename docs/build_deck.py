#!/usr/bin/env python3
"""Build the AgentGuard deck.

Content lives in ``docs/deck.json``; layout lives here. Written against
python-pptx directly rather than through a generic spec converter so the
geometry, table styling and auto-fit are predictable — there is no LibreOffice
on this host to render-check the result, so the builder has to be conservative:

* blank layout + explicit text boxes (no placeholder inheritance surprises)
* an auto-fit pass that shrinks bullet text until the estimated height fits
* tables with an explicit header fill, zebra rows and a fixed 11.5 pt body
* a footer with the repo path and the slide number on every content slide

Usage:
    python docs/build_deck.py docs/deck.json docs/AgentGuard-deck.pptx
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

INK = RGBColor(0x0F, 0x17, 0x2A)
MUTED = RGBColor(0x64, 0x74, 0x8B)
ACCENT = RGBColor(0x0E, 0x74, 0x90)
ACCENT_SOFT = RGBColor(0xE0, 0xF2, 0xF7)
RULE = RGBColor(0xE2, 0xE8, 0xF0)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
ZEBRA = RGBColor(0xF8, 0xFA, 0xFC)

SLIDE_W, SLIDE_H = 13.333, 7.5
MARGIN = 0.62
BODY_W = SLIDE_W - 2 * MARGIN


def rgb(value: str | None, fallback: RGBColor = INK) -> RGBColor:
    if not value:
        return fallback
    return RGBColor.from_string(value.replace("#", "").upper())


# --------------------------------------------------------------------------- text


def est_lines(text: str, size: float, width_in: float) -> int:
    """Rough line count: Calibri averages ~0.5 em per character."""
    chars_per_line = max(8, int((width_in * 72) / (size * 0.5)))
    return max(1, math.ceil(len(text) / chars_per_line))


def fit_bullets(bullets: list[dict], width_in: float, height_in: float, max_size: float = 20.0) -> list[dict]:
    """Shrink every bullet proportionally until the block fits the box."""
    scale = 1.0
    for _ in range(40):
        total = 0.0
        for bullet in bullets:
            size = float(bullet.get("size", max_size)) * scale
            indent = 0.55 if int(bullet.get("level", 0)) else 0.0
            lines = est_lines(str(bullet.get("text", "")), size, width_in - 0.4 - indent)
            total += lines * size * 1.32 + size * 0.42
        if total <= height_in * 72 or scale < 0.55:
            break
        scale -= 0.03
    out = []
    for bullet in bullets:
        copy = dict(bullet)
        copy["size"] = round(float(bullet.get("size", max_size)) * scale, 1)
        out.append(copy)
    return out


def add_text(slide, text, *, left, top, width, height, size=18, color=INK, bold=False,
             italic=False, font="Calibri", align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    frame = box.text_frame
    frame.word_wrap = True
    frame.vertical_anchor = anchor
    frame.margin_left = frame.margin_right = Emu(0)
    frame.margin_top = frame.margin_bottom = Emu(0)
    for index, line in enumerate(str(text).split("\n")):
        para = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        para.alignment = align
        para.space_after = Pt(size * 0.45)
        run = para.add_run()
        run.text = line
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.italic = italic
        run.font.name = font
        run.font.color.rgb = color
    return box


def add_bullets(slide, bullets, *, left, top, width, height, max_size=20.0):
    bullets = fit_bullets(bullets, width, height, max_size)
    box = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    frame = box.text_frame
    frame.word_wrap = True
    frame.margin_left = frame.margin_right = Emu(0)
    frame.margin_top = frame.margin_bottom = Emu(0)
    for index, bullet in enumerate(bullets):
        level = int(bullet.get("level", 0))
        size = float(bullet.get("size", max_size))
        para = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        para.level = min(level, 4)
        para.space_before = Pt(size * (0.5 if level else 0.75))
        para.space_after = Pt(size * 0.18)
        prefix = "— " if level else ""
        run = para.add_run()
        run.text = prefix + str(bullet.get("text", ""))
        run.font.size = Pt(size)
        run.font.bold = bool(bullet.get("bold"))
        run.font.italic = bool(bullet.get("italic"))
        run.font.name = str(bullet.get("font", "Calibri"))
        run.font.color.rgb = rgb(bullet.get("color"), INK if not level else MUTED)
    return box


# ------------------------------------------------------------------------- furniture


def add_rule(slide, *, top=0.0, height=0.2, color=ACCENT):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(top), Inches(SLIDE_W), Inches(height))
    shape.fill.solid()
    shape.fill.fore_color.rgb = color
    shape.line.fill.background()
    shape.shadow.inherit = False
    return shape


def add_footer(slide, index: int, total: int, label: str):
    text = f"{label}   ·   {index} / {total}"
    box = add_text(slide, text, left=SLIDE_W - 3.6, top=SLIDE_H - 0.5, width=3.0, height=0.3,
                   size=9, color=MUTED, align=PP_ALIGN.RIGHT)


def add_header(slide, title: str, *, size=30):
    add_text(slide, title, left=MARGIN, top=0.5, width=BODY_W, height=0.85, size=size, bold=True)
    line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(MARGIN), Inches(1.36), Inches(1.1), Inches(0.045))
    line.fill.solid()
    line.fill.fore_color.rgb = ACCENT
    line.line.fill.background()
    line.shadow.inherit = False


# ----------------------------------------------------------------------- tables


def add_table(slide, spec):
    rows = spec["rows"]
    n_rows, n_cols = len(rows), len(rows[0])
    left, top = float(spec.get("left", MARGIN)), float(spec.get("top", 2.0))
    width = float(spec.get("width", BODY_W))
    height = float(spec.get("height", 0.32 * n_rows))
    body_size = float(spec.get("size", 11.5))

    shape = slide.shapes.add_table(n_rows, n_cols, Inches(left), Inches(top), Inches(width), Inches(height))
    table = shape.table

    widths = spec.get("column_widths")
    if widths:
        total = sum(float(w) for w in widths)
        for col, w in enumerate(widths):
            table.columns[col].width = Emu(int(Inches(width) * float(w) / total))
    table.rows[0].height = Inches(0.4)
    for r in range(1, n_rows):
        table.rows[r].height = Inches(0.3)

    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            cell = table.cell(r, c)
            cell.text = ""
            cell.margin_left = Inches(0.09)
            cell.margin_right = Inches(0.07)
            cell.margin_top = Inches(0.045)
            cell.margin_bottom = Inches(0.045)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            cell.fill.solid()
            if r == 0:
                cell.fill.fore_color.rgb = ACCENT
            else:
                cell.fill.fore_color.rgb = ZEBRA if r % 2 == 0 else WHITE
            para = cell.text_frame.paragraphs[0]
            run = para.add_run()
            run.text = str(value)
            run.font.size = Pt(body_size if r else body_size + 0.5)
            run.font.bold = r == 0
            run.font.name = "Calibri"
            run.font.color.rgb = WHITE if r == 0 else INK
    return shape


# ----------------------------------------------------------------------- charts


def add_chart(slide, spec):
    from pptx.chart.data import CategoryChartData
    from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION, XL_LABEL_POSITION

    data = CategoryChartData()
    data.categories = spec["categories"]
    colors = [RGBColor(0xB9, 0x1C, 0x1C), ACCENT]
    for index, (name, values) in enumerate(spec["series"].items()):
        data.add_series(name, values)

    frame = slide.shapes.add_chart(
        XL_CHART_TYPE.COLUMN_CLUSTERED,
        Inches(float(spec.get("left", MARGIN))), Inches(float(spec.get("top", 1.8))),
        Inches(float(spec.get("width", 6.2))), Inches(float(spec.get("height", 4.4))),
        data,
    )
    chart = frame.chart
    chart.has_title = bool(spec.get("title"))
    if spec.get("title"):
        chart.chart_title.text_frame.text = str(spec["title"])
        for run in chart.chart_title.text_frame.paragraphs[0].runs:
            run.font.size = Pt(13)
            run.font.bold = True
            run.font.name = "Calibri"
            run.font.color.rgb = INK
    chart.has_legend = True
    chart.legend.position = XL_LEGEND_POSITION.BOTTOM
    chart.legend.include_in_layout = False
    chart.legend.font.size = Pt(11)
    chart.legend.font.color.rgb = MUTED

    plot = chart.plots[0]
    plot.gap_width = 60
    plot.has_data_labels = True
    labels = plot.data_labels
    labels.font.size = Pt(11)
    labels.font.bold = True
    labels.font.color.rgb = INK
    labels.position = XL_LABEL_POSITION.OUTSIDE_END

    for index, series in enumerate(plot.series):
        series.format.fill.solid()
        series.format.fill.fore_color.rgb = colors[index % len(colors)]

    value_axis = chart.value_axis
    value_axis.has_major_gridlines = True
    value_axis.major_gridlines.format.line.color.rgb = RULE
    value_axis.tick_labels.font.size = Pt(9)
    value_axis.tick_labels.font.color.rgb = MUTED
    value_axis.maximum_scale = 100 if max(max(v) for v in spec["series"].values()) <= 100 else None
    category_axis = chart.category_axis
    category_axis.tick_labels.font.size = Pt(11)
    category_axis.tick_labels.font.color.rgb = INK
    return frame


# ------------------------------------------------------------------------ build


def build(spec: dict, out_path: Path) -> int:
    prs = Presentation()
    prs.slide_width = Inches(SLIDE_W)
    prs.slide_height = Inches(SLIDE_H)
    blank = prs.slide_layouts[6]
    label = str(spec.get("label", "AgentGuard"))
    slides = spec["slides"]
    total = len(slides)

    for index, slide_spec in enumerate(slides, start=1):
        slide = prs.slides.add_slide(blank)
        kind = slide_spec.get("kind", "content")

        if kind == "title":
            add_rule(slide, top=0.0, height=0.24)
            add_text(slide, slide_spec["title"], left=MARGIN, top=1.9, width=BODY_W, height=1.2,
                     size=46, bold=True)
            add_text(slide, slide_spec.get("subtitle", ""), left=MARGIN, top=3.15, width=10.6, height=2.4,
                     size=17, color=MUTED)
            add_rule(slide, top=SLIDE_H - 0.24, height=0.24, color=RULE)
            continue

        add_rule(slide, top=0.0, height=0.16)
        add_header(slide, slide_spec.get("title", ""))
        add_footer(slide, index, total, label)

        has_side = bool(slide_spec.get("tables") or slide_spec.get("charts"))
        top = 1.75
        body_height = slide_spec.get("bullets_height") or (SLIDE_H - top - 0.75)

        if slide_spec.get("bullets"):
            width = 5.6 if (has_side and slide_spec.get("side_by_side", True)) else BODY_W
            add_bullets(slide, slide_spec["bullets"], left=MARGIN, top=top, width=width, height=body_height)

        for table in slide_spec.get("tables", []):
            add_table(slide, table)
        for chart in slide_spec.get("charts", []):
            add_chart(slide, chart)

        for extra in slide_spec.get("textboxes", []):
            add_text(slide, extra["text"],
                     left=float(extra.get("left", MARGIN)), top=float(extra.get("top", 1.8)),
                     width=float(extra.get("width", 5.4)), height=float(extra.get("height", 2.4)),
                     size=float(extra.get("size", 13)), color=rgb(extra.get("color"), MUTED),
                     bold=bool(extra.get("bold")), italic=bool(extra.get("italic", True)))

    prs.save(str(out_path))
    return len(slides)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    spec = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    count = build(spec, Path(argv[2]))
    print(json.dumps({"ok": True, "output": argv[2], "slides": count}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
