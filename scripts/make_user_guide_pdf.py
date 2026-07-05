from __future__ import annotations

import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "USER_GUIDE.md"
TARGET = ROOT / "docs" / "EVTXAuditor_User_Guide.pdf"


def register_fonts() -> tuple[str, str]:
    candidates = [
        (
            Path(r"C:\Windows\Fonts\arial.ttf"),
            Path(r"C:\Windows\Fonts\arialbd.ttf"),
            "Arial",
            "Arial-Bold",
        ),
        (
            Path(r"C:\Windows\Fonts\segoeui.ttf"),
            Path(r"C:\Windows\Fonts\segoeuib.ttf"),
            "SegoeUI",
            "SegoeUI-Bold",
        ),
    ]
    for regular, bold, regular_name, bold_name in candidates:
        if regular.exists() and bold.exists():
            pdfmetrics.registerFont(TTFont(regular_name, str(regular)))
            pdfmetrics.registerFont(TTFont(bold_name, str(bold)))
            return regular_name, bold_name
    return "Helvetica", "Helvetica-Bold"


FONT, FONT_BOLD = register_fonts()


def make_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "TitleRu",
            parent=base["Title"],
            fontName=FONT_BOLD,
            fontSize=20,
            leading=24,
            alignment=TA_CENTER,
            spaceAfter=8 * mm,
        ),
        "h2": ParagraphStyle(
            "Heading2Ru",
            parent=base["Heading2"],
            fontName=FONT_BOLD,
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1f3a5f"),
            spaceBefore=4 * mm,
            spaceAfter=2 * mm,
        ),
        "h3": ParagraphStyle(
            "Heading3Ru",
            parent=base["Heading3"],
            fontName=FONT_BOLD,
            fontSize=11.5,
            leading=15,
            textColor=colors.HexColor("#2f4f6f"),
            spaceBefore=3 * mm,
            spaceAfter=1.5 * mm,
        ),
        "body": ParagraphStyle(
            "BodyRu",
            parent=base["BodyText"],
            fontName=FONT,
            fontSize=10,
            leading=14,
            spaceAfter=2.2 * mm,
        ),
        "bullet": ParagraphStyle(
            "BulletRu",
            parent=base["BodyText"],
            fontName=FONT,
            fontSize=10,
            leading=14,
            leftIndent=7 * mm,
            firstLineIndent=-4 * mm,
            spaceAfter=1.2 * mm,
        ),
        "code": ParagraphStyle(
            "CodeRu",
            parent=base["Code"],
            fontName=FONT,
            fontSize=8.5,
            leading=11,
            leftIndent=4 * mm,
            rightIndent=4 * mm,
            backColor=colors.HexColor("#f4f6f8"),
            borderColor=colors.HexColor("#d8dee6"),
            borderWidth=0.4,
            borderPadding=5,
            spaceBefore=1 * mm,
            spaceAfter=3 * mm,
        ),
    }


STYLES = make_styles()


def inline(text: str) -> str:
    escaped = html.escape(text)
    escaped = re.sub(
        r"`([^`]+)`",
        lambda match: f"<font name=\"{FONT_BOLD}\">{match.group(1)}</font>",
        escaped,
    )
    escaped = escaped.replace(" - ", " &mdash; ")
    return escaped


def flush_paragraph(story: list, paragraph_lines: list[str]) -> None:
    if not paragraph_lines:
        return
    text = " ".join(line.strip() for line in paragraph_lines if line.strip())
    if text:
        story.append(Paragraph(inline(text), STYLES["body"]))
    paragraph_lines.clear()


def markdown_to_story(markdown: str) -> list:
    story: list = []
    paragraph_lines: list[str] = []
    code_lines: list[str] = []
    in_code = False
    first_heading = True

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()

        if line.startswith("```"):
            flush_paragraph(story, paragraph_lines)
            if in_code:
                code = "\n".join(code_lines).strip("\n")
                story.append(Preformatted(code, STYLES["code"]))
                code_lines.clear()
                in_code = False
            else:
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not line.strip():
            flush_paragraph(story, paragraph_lines)
            continue

        if line.startswith("# "):
            flush_paragraph(story, paragraph_lines)
            if not first_heading:
                story.append(PageBreak())
            story.append(Paragraph(inline(line[2:].strip()), STYLES["title"]))
            first_heading = False
            continue

        if line.startswith("## "):
            flush_paragraph(story, paragraph_lines)
            story.append(Paragraph(inline(line[3:].strip()), STYLES["h2"]))
            continue

        if line.startswith("### "):
            flush_paragraph(story, paragraph_lines)
            story.append(Paragraph(inline(line[4:].strip()), STYLES["h3"]))
            continue

        if line.startswith("- "):
            flush_paragraph(story, paragraph_lines)
            story.append(Paragraph(inline(line[2:].strip()), STYLES["bullet"], bulletText="-"))
            continue

        numbered = re.match(r"^(\d+)\.\s+(.*)$", line)
        if numbered:
            flush_paragraph(story, paragraph_lines)
            story.append(
                Paragraph(
                    inline(numbered.group(2).strip()),
                    STYLES["bullet"],
                    bulletText=f"{numbered.group(1)}.",
                )
            )
            continue

        paragraph_lines.append(line)

    flush_paragraph(story, paragraph_lines)
    if code_lines:
        story.append(Preformatted("\n".join(code_lines), STYLES["code"]))
    return story


def draw_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont(FONT, 8)
    canvas.setFillColor(colors.HexColor("#5b6673"))
    canvas.drawString(18 * mm, 10 * mm, "Разработал: Абдрахманов Амаль Даулетович")
    canvas.drawRightString(192 * mm, 10 * mm, f"Страница {doc.page}")
    canvas.restoreState()


def build_pdf() -> None:
    markdown = SOURCE.read_text(encoding="utf-8")
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(TARGET),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title="EVTX Auditor - инструкция пользователя",
        author="Абдрахманов Амаль Даулетович",
        subject="Инструкция пользователя EVTX Auditor",
    )
    story = markdown_to_story(markdown)
    story.append(Spacer(1, 4 * mm))
    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)


if __name__ == "__main__":
    build_pdf()
    print(TARGET)
