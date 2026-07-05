from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path


GITHUB_REPO = "https://github.com/Amtonsi/evtx-auditor"
GITHUB_README = f"{GITHUB_REPO}#readme"
GITHUB_PDF = f"{GITHUB_REPO}/blob/main/docs/EVTXAuditor_User_Guide.pdf"


def _font_path(*names: str) -> Path | None:
    for name in names:
        candidate = Path("C:/Windows/Fonts") / name
        if candidate.exists():
            return candidate
    return None


def build_pdf(output_path: str | Path) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise SystemExit(
            "reportlab is required to build the PDF guide. "
            "Install it with: python -m pip install reportlab"
        ) from exc

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    regular_font = "Helvetica"
    bold_font = "Helvetica-Bold"
    regular_path = _font_path("segoeui.ttf", "arial.ttf", "calibri.ttf")
    bold_path = _font_path("segoeuib.ttf", "arialbd.ttf", "calibrib.ttf")
    if regular_path is not None:
        pdfmetrics.registerFont(TTFont("GuideRegular", str(regular_path)))
        regular_font = "GuideRegular"
    if bold_path is not None:
        pdfmetrics.registerFont(TTFont("GuideBold", str(bold_path)))
        bold_font = "GuideBold"
    elif regular_path is not None:
        bold_font = regular_font

    page_width, page_height = landscape(A4)
    margin = 22 * mm
    c = canvas.Canvas(str(output), pagesize=landscape(A4))
    c.setTitle("EVTX Auditor - подробная инструкция пользователя")
    c.setAuthor("Абдрахманов Амаль Даулетович")
    c.setSubject("Проверка архивов журналов Windows EVTX/EVT и формирование HTML-отчета")

    ink = colors.HexColor("#172126")
    muted = colors.HexColor("#64748B")
    bg = colors.HexColor("#F3F6F8")
    panel = colors.white
    line = colors.HexColor("#DCE3E7")
    navy = colors.HexColor("#172126")
    teal = colors.HexColor("#0F766E")
    teal_dark = colors.HexColor("#115E59")
    blue = colors.HexColor("#2563EB")
    violet = colors.HexColor("#6D4AFF")
    amber = colors.HexColor("#B45309")
    red = colors.HexColor("#B91C1C")
    green = colors.HexColor("#15803D")
    light_teal = colors.HexColor("#DDF7F3")
    light_blue = colors.HexColor("#E8F0FF")
    light_violet = colors.HexColor("#F0EDFF")
    light_amber = colors.HexColor("#FFF1E7")
    light_red = colors.HexColor("#FEE2E2")
    light_green = colors.HexColor("#DCFCE7")
    light_gray = colors.HexColor("#E2E8F0")

    def set_font(size: float, bold: bool = False, color=ink) -> None:
        c.setFont(bold_font if bold else regular_font, size)
        c.setFillColor(color)

    def text_width(text: str, size: float, bold: bool = False) -> float:
        return c.stringWidth(text, bold_font if bold else regular_font, size)

    def draw_wrapped(
        text: str,
        x: float,
        y: float,
        max_width: float,
        size: float = 10.5,
        leading: float = 14,
        bold: bool = False,
        color=ink,
    ) -> float:
        set_font(size, bold=bold, color=color)
        for paragraph in text.split("\n"):
            words = paragraph.split()
            if not words:
                y -= leading
                continue
            line_text = ""
            for word in words:
                candidate = f"{line_text} {word}".strip()
                if text_width(candidate, size, bold=bold) <= max_width or not line_text:
                    line_text = candidate
                else:
                    c.drawString(x, y, line_text)
                    y -= leading
                    line_text = word
            if line_text:
                c.drawString(x, y, line_text)
                y -= leading
        return y

    def card(x: float, y: float, w: float, h: float, fill=panel, stroke=line, radius: float = 10) -> None:
        c.setFillColor(fill)
        c.setStrokeColor(stroke)
        c.roundRect(x, y, w, h, radius, stroke=1, fill=1)

    def pill(text: str, x: float, y: float, fill, color=ink, pad: float = 8) -> float:
        set_font(8.8, bold=True, color=color)
        w = text_width(text, 8.8, bold=True) + pad * 2
        c.setFillColor(fill)
        c.roundRect(x, y, w, 19, 9.5, stroke=0, fill=1)
        set_font(8.8, bold=True, color=color)
        c.drawString(x + pad, y + 5.5, text)
        return x + w + 6

    def draw_link(label: str, url: str, x: float, y: float, size: float = 10.5) -> float:
        set_font(size, color=blue)
        c.drawString(x, y, label)
        w = text_width(label, size)
        c.linkURL(url, (x, y - 2, x + w, y + size + 2), relative=0)
        c.setStrokeColor(blue)
        c.line(x, y - 2, x + w, y - 2)
        return x + w

    def bullet_list(items: list[str], x: float, y: float, max_width: float, color_dot=teal) -> float:
        for item in items:
            c.setFillColor(color_dot)
            c.circle(x + 3, y + 4, 2.4, stroke=0, fill=1)
            y = draw_wrapped(item, x + 13, y, max_width - 13, size=9.8, leading=13.3)
            y -= 2
        return y

    def code_box(lines: list[str], x: float, y: float, w: float, h: float) -> None:
        card(x, y, w, h, fill=colors.HexColor("#FFFFFF"), stroke=line, radius=7)
        c.setFillColor(colors.HexColor("#F8FAFC"))
        c.roundRect(x + 8, y + 8, w - 16, h - 16, 5, stroke=0, fill=1)
        set_font(8.6, color=ink)
        yy = y + h - 24
        for line_text in lines:
            c.drawString(x + 18, yy, line_text)
            yy -= 12

    def label_box(
        title: str,
        body: str,
        x: float,
        y: float,
        w: float,
        h: float,
        fill=panel,
        title_color=ink,
    ) -> None:
        card(x, y, w, h, fill=fill)
        set_font(11.5, bold=True, color=title_color)
        c.drawString(x + 12, y + h - 22, title)
        draw_wrapped(body, x + 12, y + h - 42, w - 24, size=9.2, leading=12.2, color=muted)

    def arrow(x1: float, y1: float, x2: float, y2: float, color=teal) -> None:
        c.setStrokeColor(color)
        c.setLineWidth(2.0)
        c.line(x1, y1, x2, y2)
        if x2 >= x1:
            points = [(x2, y2), (x2 - 8, y2 + 5), (x2 - 8, y2 - 5)]
        else:
            points = [(x2, y2), (x2 + 8, y2 + 5), (x2 + 8, y2 - 5)]
        c.setFillColor(color)
        path = c.beginPath()
        path.moveTo(points[0][0], points[0][1])
        path.lineTo(points[1][0], points[1][1])
        path.lineTo(points[2][0], points[2][1])
        path.close()
        c.drawPath(path, stroke=0, fill=1)

    def section_header(title: str, page: int) -> None:
        c.setFillColor(bg)
        c.rect(0, 0, page_width, page_height, stroke=0, fill=1)
        c.setFillColor(navy)
        c.rect(0, page_height - 58, page_width, 58, stroke=0, fill=1)
        set_font(19, bold=True, color=colors.white)
        c.drawString(margin, page_height - 36, title)
        set_font(9, color=colors.HexColor("#B8C4C9"))
        c.drawRightString(page_width - margin, page_height - 34, "EVTX Auditor")
        set_font(8.3, color=muted)
        c.drawString(margin, 18, "GitHub:")
        draw_link(GITHUB_REPO, GITHUB_REPO, margin + 38, 18, size=8.3)
        set_font(8.3, color=muted)
        c.drawRightString(page_width - margin, 18, f"Страница {page}")

    def draw_cover_window(x: float, y: float, w: float, h: float) -> None:
        card(x, y, w, h, fill=colors.white, radius=10)
        header_h = 56
        rail_w = 98
        c.setFillColor(navy)
        c.rect(x, y + h - header_h, w, header_h, stroke=0, fill=1)
        set_font(13, bold=True, color=colors.white)
        c.drawString(x + 14, y + h - 29, "EVTX Auditor")
        set_font(6.5, color=colors.HexColor("#B8C4C9"))
        c.drawString(x + 14, y + h - 43, "Проверка журналов Windows")
        c.setFillColor(teal)
        c.roundRect(x + w - 76, y + h - 40, 58, 24, 7, stroke=0, fill=1)
        set_font(7.2, bold=True, color=colors.white)
        c.drawCentredString(x + w - 47, y + h - 31, "Готово")

        body_h = h - header_h
        c.setFillColor(colors.white)
        c.rect(x, y, rail_w, body_h, stroke=0, fill=1)
        c.setStrokeColor(line)
        c.line(x + rail_w, y, x + rail_w, y + body_h)
        set_font(6.5, bold=True, color=muted)
        c.drawString(x + 12, y + body_h - 24, "АНАЛИЗ")

        def nav_button(text: str, yy: float, active: bool = False) -> None:
            c.setFillColor(teal if active else colors.HexColor("#EDF2F4"))
            c.roundRect(x + 12, yy, rail_w - 24, 23, 5, stroke=0, fill=1)
            set_font(6.5, bold=True, color=colors.white if active else ink)
            c.drawCentredString(x + rail_w / 2, yy + 8, text)

        nav_button("Архивы ZIP", y + body_h - 58, active=True)
        nav_button("EVTX + EVT", y + body_h - 88)
        nav_button("HTML-отчет", y + body_h - 118)
        set_font(6.2, color=muted)
        c.drawString(x + 12, y + 28, "Разработал:")
        c.drawString(x + 12, y + 17, "Абдрахманов А.Д.")

        content_x = x + rail_w + 12
        content_w = w - rail_w - 24
        panels = [
            ("Папка с архивами", r"C:\Users\impal\Downloads\АУДИТ 2"),
            ("Формат", "Application / Security / System"),
            ("Отчет", "один HTML по всем узлам"),
        ]
        for idx, (title_text, value) in enumerate(panels):
            yy = y + h - header_h - 18 - idx * 46 - 34
            card(content_x, yy, content_w, 34, fill=colors.white, radius=5)
            set_font(7, bold=True, color=muted)
            c.drawString(content_x + 8, yy + 21, title_text)
            set_font(6.4, bold=True, color=ink)
            c.drawString(content_x + 8, yy + 9, value[:42])
        log_y = y + 24
        card(content_x, log_y, content_w, 65, fill=colors.white, radius=5)
        set_font(7, bold=True, color=ink)
        c.drawString(content_x + 8, log_y + 48, "Прогресс")
        c.setFillColor(colors.HexColor("#DDE6E8"))
        c.rect(content_x + 8, log_y + 33, content_w - 16, 7, stroke=0, fill=1)
        c.setFillColor(teal)
        c.rect(content_x + 8, log_y + 33, (content_w - 16) * 0.72, 7, stroke=0, fill=1)
        set_font(5.7, color=muted)
        c.drawString(content_x + 8, log_y + 18, "Security.evtx: группировка событий")

    def draw_gui_mockup(x: float, y: float, w: float, h: float) -> None:
        card(x, y, w, h, fill=colors.white, radius=9)
        c.setFillColor(navy)
        c.roundRect(x, y + h - 56, w, 56, 9, stroke=0, fill=1)
        set_font(16, bold=True, color=colors.white)
        c.drawString(x + 18, y + h - 33, "EVTX Auditor")
        set_font(8, color=colors.HexColor("#B8C4C9"))
        c.drawString(x + 18, y + h - 47, "Настольная проверка архивов событий Windows")
        content_x = x + 18
        yy = y + h - 92
        for title_text, value in [
            ("Папка с архивами", r"C:\Users\impal\Downloads\АУДИТ 2"),
            ("Папка отчета", r"C:\Users\impal\Documents\Codex\outputs"),
        ]:
            card(content_x, yy - 30, w - 36, 34, fill=colors.HexColor("#F8FAFC"), radius=5)
            set_font(7.8, bold=True, color=muted)
            c.drawString(content_x + 10, yy - 9, title_text)
            set_font(8.1, color=ink)
            c.drawString(content_x + 120, yy - 9, value)
            c.setFillColor(light_blue)
            c.roundRect(x + w - 84, yy - 24, 52, 20, 7, stroke=0, fill=1)
            set_font(7.3, bold=True, color=blue)
            c.drawCentredString(x + w - 58, yy - 17, "Выбрать")
            yy -= 47
        c.setFillColor(teal)
        c.roundRect(content_x, yy - 34, 150, 30, 8, stroke=0, fill=1)
        set_font(8.8, bold=True, color=colors.white)
        c.drawCentredString(content_x + 75, yy - 23, "Начать проверку")
        c.setFillColor(light_amber)
        c.roundRect(content_x + 166, yy - 34, 92, 30, 8, stroke=0, fill=1)
        set_font(8.8, bold=True, color=amber)
        c.drawCentredString(content_x + 212, yy - 23, "Отменить")
        yy -= 58
        card(content_x, y + 28, w - 36, yy - y - 18, fill=colors.HexColor("#F8FAFC"), radius=6)
        set_font(8.4, bold=True, color=ink)
        c.drawString(content_x + 10, yy - 10, "Журнал выполнения")
        set_font(7.2, color=muted)
        lines = [
            "Найдено 2 узла и 6 журналов",
            "NODE-01: Security.evtx, System.evtx",
            "NODE-02: Application.evt - legacy parser",
            "Отчет создан: EVTX_Audit_2026-07-06.html",
        ]
        ly = yy - 30
        for line_text in lines:
            c.drawString(content_x + 14, ly, line_text)
            ly -= 14

    def draw_report_mockup(x: float, y: float, w: float, h: float) -> None:
        card(x, y, w, h, fill=colors.white, radius=9)
        rail_w = 142
        c.setFillColor(navy)
        c.rect(x, y + h - 50, w, 50, stroke=0, fill=1)
        set_font(13, bold=True, color=colors.white)
        c.drawString(x + 16, y + h - 31, "EVTX Audit Report")
        c.setFillColor(colors.white)
        c.rect(x, y, rail_w, h - 50, stroke=0, fill=1)
        c.setStrokeColor(line)
        c.line(x + rail_w, y, x + rail_w, y + h - 50)
        nav = ["Общая сводка", "Критические", "Безопасность", "Узлы", "Качество данных"]
        yy = y + h - 76
        for idx, item in enumerate(nav):
            c.setFillColor(teal if idx == 0 else colors.HexColor("#EDF2F4"))
            c.roundRect(x + 12, yy - idx * 30, rail_w - 24, 22, 5, stroke=0, fill=1)
            set_font(7, bold=True, color=colors.white if idx == 0 else ink)
            c.drawString(x + 22, yy + 7 - idx * 30, item)
        cx = x + rail_w + 16
        set_font(9, bold=True, color=ink)
        c.drawString(cx, y + h - 78, "Сводка по узлам")
        for idx, (name, status, fill, color) in enumerate(
            [
                ("NODE-01", "Есть находки", light_red, red),
                ("NODE-02", "Неполные данные", light_amber, amber),
                ("NODE-03", "Проблем не найдено", light_green, green),
            ]
        ):
            row_y = y + h - 112 - idx * 42
            card(cx, row_y, w - rail_w - 32, 32, fill=fill, radius=5)
            set_font(8.2, bold=True, color=ink)
            c.drawString(cx + 10, row_y + 19, name)
            set_font(7.4, bold=True, color=color)
            c.drawRightString(x + w - 22, row_y + 19, status)
            set_font(6.6, color=muted)
            c.drawString(cx + 10, row_y + 7, "Critical / Error / Security, события сгруппированы")
        card(cx, y + 10, w - rail_w - 32, 38, fill=colors.HexColor("#F8FAFC"), radius=5)
        set_font(7.6, bold=True, color=ink)
        c.drawString(cx + 10, y + 35, "Пример находки: Security 4625")
        set_font(6.6, color=muted)
        c.drawString(cx + 10, y + 23, "10+ неудачных входов за 15 минут, показаны Record ID и IP")

    # Page 1 - cover
    c.setFillColor(navy)
    c.rect(0, 0, page_width, page_height, stroke=0, fill=1)
    c.setFillColor(teal)
    c.rect(0, 0, 170, page_height, stroke=0, fill=1)
    c.setFillColor(teal_dark)
    c.circle(120, page_height - 108, 84, stroke=0, fill=1)
    set_font(34, bold=True, color=colors.white)
    c.drawString(205, page_height - 145, "EVTX Auditor")
    set_font(20, color=colors.HexColor("#B8C4C9"))
    c.drawString(205, page_height - 180, "Подробная инструкция пользователя")
    y = page_height - 238
    y = draw_wrapped(
        "Локальная настольная программа для проверки архивов журналов Windows. "
        "Поддерживает современные EVTX и legacy EVT журналы Windows XP / Server 2003, "
        "формирует один подробный HTML-отчет по всем узлам.",
        205,
        y,
        320,
        size=12.5,
        leading=18,
        color=colors.white,
    )
    y -= 18
    set_font(12, color=colors.white)
    c.drawString(205, y, "Разработал: Абдрахманов Амаль Даулетович")
    y -= 25
    c.drawString(205, y, f"Дата инструкции: {date.today().strftime('%d.%m.%Y')}")
    y -= 32
    draw_link("GitHub: Amtonsi/evtx-auditor", GITHUB_REPO, 205, y, size=12)
    draw_cover_window(548, 112, 252, 308)
    c.showPage()

    # Page 2 - GitHub and purpose
    section_header("1. Назначение, состав и быстрый старт", 2)
    x = margin
    y = page_height - 96
    card(x, y - 118, 370, 118, fill=panel)
    set_font(15, bold=True)
    c.drawString(x + 16, y - 26, "GitHub-репозиторий")
    draw_link("Открыть репозиторий", GITHUB_REPO, x + 16, y - 54, size=10.5)
    draw_link("README на GitHub", GITHUB_README, x + 16, y - 78, size=10.5)
    draw_link("PDF-инструкция на GitHub", GITHUB_PDF, x + 16, y - 102, size=10.5)

    card(x + 400, y - 118, 370, 118, fill=panel)
    set_font(15, bold=True)
    c.drawString(x + 416, y - 26, "Что входит в проект")
    bullet_list(
        [
            "исходный код Python и PySide6 GUI",
            "правила анализа EVTX/EVT и тесты",
            "HTML-шаблон отчета и генератор PDF",
            "MIT License с указанием автора",
        ],
        x + 416,
        y - 54,
        335,
    )

    y -= 152
    set_font(16, bold=True)
    c.drawString(x, y, "Для чего используется")
    y -= 26
    bullet_list(
        [
            "проверить папку с ZIP-архивами журналов Windows по нескольким узлам",
            "выявить Critical, Error и важные события безопасности за последние 30 дней узла",
            "сгруппировать повторяющиеся события и сохранить доказательные поля",
            "получить один автономный HTML-отчет с общей статистикой и разделом по каждому узлу",
        ],
        x,
        y,
        430,
    )

    card(x + 470, y - 112, 300, 124, fill=light_teal)
    set_font(14, bold=True, color=teal)
    c.drawString(x + 486, y - 20, "Ключевой принцип")
    draw_wrapped(
        "Приложение читает архивы локально и не отправляет журналы в сеть. "
        "Если журнал поврежден или часть данных недоступна, отчет явно показывает "
        "статус неполных данных, а не скрывает проблему.",
        x + 486,
        y - 44,
        268,
        size=10.2,
        leading=13.5,
    )
    c.showPage()

    # Page 3 - operator workflow
    section_header("2. Сценарий работы оператора", 3)
    draw_gui_mockup(margin, page_height - 360, 370, 258)
    x = margin + 405
    y = page_height - 106
    steps = [
        ("1. Выбрать папку", r"C:\Users\impal\Downloads\АУДИТ 2 или другой каталог с ZIP."),
        ("2. Выбрать выход", "папка, куда будет сохранен автономный HTML-отчет."),
        ("3. Запустить проверку", "GUI остается отзывчивым, ход анализа виден в журнале."),
        ("4. Открыть отчет", "после завершения можно открыть HTML или папку результата."),
    ]
    for idx, (title_text, body) in enumerate(steps):
        yy = y - idx * 78
        label_box(title_text, body, x, yy - 58, 340, 58, fill=panel, title_color=teal if idx < 2 else blue)
    y -= 330
    card(margin, 74, page_width - margin * 2, 70, fill=light_amber)
    set_font(13, bold=True, color=amber)
    c.drawString(margin + 16, 118, "Практическое правило")
    draw_wrapped(
        "Если узел получил статус Неполные данные или Ошибка обработки, это не означает отсутствие проблем. "
        "Такой узел требует ручной проверки исходных архивов и доступности журналов.",
        margin + 16,
        98,
        page_width - margin * 2 - 32,
        size=10.2,
        leading=13.5,
    )
    c.showPage()

    # Page 4 - input and pipeline
    section_header("3. Входные данные и поток обработки", 4)
    x = margin
    y = page_height - 104
    set_font(16, bold=True)
    c.drawString(x, y, "Рекомендуемая структура папки")
    code_box(
        [
            r"C:\Users\impal\Downloads\АУДИТ 2",
            r"  NODE-01\logs_01.zip",
            r"  NODE-01\logs_02.zip",
            r"  NODE-02\audit.zip",
            r"  NODE-03\windows_logs.zip",
        ],
        x,
        y - 112,
        345,
        94,
    )
    label_box(
        "Что извлекается из ZIP",
        "Application.evtx, Security.evtx, System.evtx, а также Application.evt, Security.evt и System.evt. "
        "Остальные файлы игнорируются.",
        x + 390,
        y - 112,
        380,
        94,
        fill=light_blue,
        title_color=blue,
    )

    y -= 168
    set_font(16, bold=True)
    c.drawString(x, y, "Поток обработки")
    y -= 36
    box_w = 104
    gap = 18
    steps = [
        ("1. Поиск", "ZIP-архивы\nпо папкам узлов"),
        ("2. Извлечение", "только EVTX/EVT\nбез path traversal"),
        ("3. Парсинг", "XML EVTX или\nWindows EVT API"),
        ("4. Правила", "Critical, Error,\nSecurity"),
        ("5. Корреляция", "4625 и повторы\nпо 15 минут"),
        ("6. HTML", "сводка и разделы\nкаждого узла"),
    ]
    for idx, (title_text, body) in enumerate(steps):
        xx = x + idx * (box_w + gap)
        fill = light_green if idx == len(steps) - 1 else panel
        color = green if idx == len(steps) - 1 else teal
        label_box(title_text, body, xx, y - 82, box_w, 82, fill=fill, title_color=color)
        if idx < len(steps) - 1:
            arrow(xx + box_w + 2, y - 42, xx + box_w + gap - 4, y - 42)

    y -= 128
    card(x, y - 72, page_width - margin * 2, 72, fill=light_red)
    set_font(13, bold=True, color=red)
    c.drawString(x + 16, y - 24, "Защита при чтении архивов")
    draw_wrapped(
        "ZIP открываются только для чтения. Временные файлы создаются в рабочей папке и удаляются после обработки. "
        "Небезопасные пути внутри ZIP отклоняются, чтобы архив не мог записать файл за пределы временного каталога.",
        x + 16,
        y - 44,
        page_width - margin * 2 - 32,
        size=10.2,
        leading=13.5,
    )
    c.showPage()

    # Page 5 - rules and statuses
    section_header("4. Правила анализа и статусы узлов", 5)
    x = margin
    y = page_height - 104
    set_font(16, bold=True)
    c.drawString(x, y, "Что попадает в отчет")
    y -= 28
    columns = [
        (
            "Системные события",
            ["уровень Critical", "уровень Error", "Kernel-Power, NTFS и другие источники", "сохранение Event ID и Record ID"],
            light_red,
            red,
        ),
        (
            "Безопасность",
            ["очистка журналов", "изменение политики аудита", "пользователи и группы", "службы и Microsoft Defender"],
            light_amber,
            amber,
        ),
        (
            "Windows XP EVT",
            ["Event ID 517", "529-539 и 680", "624, 630, 642, 644", "632, 633, 636, 637, 660, 661"],
            light_blue,
            blue,
        ),
    ]
    for idx, (title_text, items, fill, color) in enumerate(columns):
        xx = x + idx * 260
        card(xx, y - 150, 235, 150, fill=fill)
        set_font(13, bold=True, color=color)
        c.drawString(xx + 14, y - 24, title_text)
        bullet_list(items, xx + 14, y - 50, 205, color_dot=color)

    y -= 200
    set_font(16, bold=True)
    c.drawString(x, y, "Статусы узлов")
    y -= 32
    statuses = [
        ("Есть находки", "обнаружены критические, ошибочные или security-события", light_red, red),
        ("Проблем не найдено", "доступные данные обработаны, правила не сработали", light_green, green),
        ("Неполные данные", "часть архивов, журналов или записей не прочитана", light_amber, amber),
        ("Ошибка обработки", "данных недостаточно для надежного вывода", light_gray, muted),
    ]
    for idx, (name, desc, fill, color) in enumerate(statuses):
        xx = x + idx * 198
        card(xx, y - 72, 180, 72, fill=fill)
        pill(name, xx + 12, y - 30, colors.white, color=color, pad=7)
        draw_wrapped(desc, xx + 12, y - 48, 154, size=9.0, leading=11.8, color=ink)

    y -= 112
    label_box(
        "Массовые неудачные входы",
        "Event ID 4625 становится отдельной находкой, когда для одной учетной записи или одного IP найдено 10 и более попыток входа за 15 минут.",
        x,
        y - 66,
        370,
        66,
        fill=panel,
        title_color=teal,
    )
    label_box(
        "Период 30 дней",
        "Период считается от самого позднего корректного события конкретного узла, а не от текущего времени компьютера.",
        x + 405,
        y - 66,
        365,
        66,
        fill=panel,
        title_color=blue,
    )
    c.showPage()

    # Page 6 - HTML report
    section_header("5. HTML-отчет в WinAudit-подобной логике", 6)
    draw_report_mockup(margin, page_height - 360, 392, 258)
    x = margin + 430
    y = page_height - 104
    set_font(16, bold=True)
    c.drawString(x, y, "Структура отчета")
    y -= 28
    bullet_list(
        [
            "слева - навигация по сводке, критическим событиям, security-блоку и узлам",
            "сверху - общая статистика по архивам, журналам, узлам и находкам",
            "внутри узла - карточки сгруппированных событий и исходные доказательные поля",
            "в конце - контроль качества данных и диагностические сообщения",
        ],
        x,
        y,
        330,
    )
    y -= 128
    label_box(
        "Группировка повторов",
        "Повторы объединяются в одну карточку, но отчет сохраняет время первого и последнего события, количество, Record ID и технические поля.",
        x,
        y - 72,
        330,
        72,
        fill=light_teal,
        title_color=teal,
    )
    label_box(
        "Автономность",
        "HTML не требует интернет-ресурсов. Текст событий экранируется перед вставкой в отчет.",
        x,
        y - 160,
        330,
        72,
        fill=light_blue,
        title_color=blue,
    )
    c.showPage()

    # Page 7 - EVTX/EVT specifics
    section_header("6. EVTX, EVT и ограничения старых журналов", 7)
    x = margin
    y = page_height - 104
    label_box(
        "EVTX",
        "Современные журналы Windows читаются через python-evtx. Если в архивном событии есть RenderingInfo, отчет использует его. Если текста нет, показываются Event ID, Provider, Channel и EventData.",
        x,
        y - 112,
        370,
        112,
        fill=panel,
        title_color=teal,
    )
    label_box(
        "EVT Windows XP / Server 2003",
        "Legacy EVT читается через классический Windows Event Log API. На современной машине старые message DLL могут отсутствовать, поэтому полное текстовое описание события иногда недоступно.",
        x + 400,
        y - 112,
        370,
        112,
        fill=panel,
        title_color=blue,
    )
    y -= 150
    set_font(16, bold=True)
    c.drawString(x, y, "Что сохраняется даже без полного текста")
    y -= 30
    fields = ["Event ID", "Source", "Computer", "EventType", "RecordNumber", "TimeGenerated", "Category", "строки события"]
    tx = x
    ty = y
    for idx, field in enumerate(fields):
        tx = pill(field, tx, ty, light_gray, color=ink, pad=8)
        if tx > page_width - margin - 125:
            tx = x
            ty -= 28
    y = ty - 42
    card(x, y - 84, page_width - margin * 2, 84, fill=light_amber)
    set_font(13, bold=True, color=amber)
    c.drawString(x + 16, y - 24, "Ограничение интерпретации")
    draw_wrapped(
        "Программа не придумывает отсутствующие описания поставщика события. "
        "Если текст недоступен, отчет прямо показывает технические поля и применяет правила по Event ID и нормализованным данным.",
        x + 16,
        y - 46,
        page_width - margin * 2 - 32,
        size=10.2,
        leading=13.5,
    )
    y -= 126
    label_box(
        "NTFS и системные ошибки",
        "Да. Ошибки NTFS учитываются как события уровня Error/Critical и попадают в системный раздел отчета с источником, Event ID и доказательными полями.",
        x,
        y - 62,
        370,
        62,
        fill=light_red,
        title_color=red,
    )
    label_box(
        "Windows XP",
        "Да. Одно приложение понимает и EVTX, и EVT, поэтому архивы современных Windows и Windows XP можно проверять в одном сценарии.",
        x + 400,
        y - 62,
        370,
        62,
        fill=light_green,
        title_color=green,
    )
    c.showPage()

    # Page 8 - build, privacy, license
    section_header("7. Сборка, проверка, приватность и лицензия", 8)
    x = margin
    y = page_height - 104
    set_font(16, bold=True)
    c.drawString(x, y, "Команды")
    commands = [
        ("Установка", r".\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt"),
        ("Запуск GUI", r".\.venv\Scripts\python.exe -m evtx_auditor.main"),
        ("Тесты", r".\.venv\Scripts\python.exe -m pytest -v"),
        ("Сборка EXE", r"powershell -ExecutionPolicy Bypass -File scripts\build.ps1"),
        ("Сборка PDF", r"python scripts\make_user_guide_pdf.py"),
    ]
    table_w = 500
    row_h = 38
    card(x, y - row_h * len(commands) - 18, table_w, row_h * len(commands) + 18, fill=panel)
    yy = y - 28
    for label, command in commands:
        set_font(9.4, bold=True, color=ink)
        c.drawString(x + 14, yy, label)
        draw_wrapped(command, x + 132, yy, table_w - 150, size=8.4, leading=10.5, color=muted)
        yy -= row_h
        c.setStrokeColor(colors.HexColor("#EEF2F4"))
        c.line(x + 10, yy + 14, x + table_w - 10, yy + 14)

    label_box(
        "MIT License",
        "Проект распространяется под лицензией MIT. Авторские права: 2026, Абдрахманов Амаль Даулетович.",
        x + 535,
        y - 92,
        235,
        74,
        fill=light_green,
        title_color=green,
    )
    label_box(
        "Что не публикуется",
        "Реальные ZIP, EVTX, EVT, HTML-отчеты, outputs, dist, build, work и виртуальное окружение остаются локально.",
        x + 535,
        y - 186,
        235,
        74,
        fill=light_red,
        title_color=red,
    )

    y -= 260
    set_font(16, bold=True)
    c.drawString(x, y, "Граница приватности")
    y -= 28
    safe_w = 360
    card(x, y - 132, safe_w, 132, fill=light_green)
    set_font(13, bold=True, color=green)
    c.drawString(x + 16, y - 24, "Можно публиковать")
    bullet_list(["src, tests, scripts", "README, LICENSE", "docs/USER_GUIDE.md и PDF", "pyproject.toml и requirements"], x + 16, y - 50, safe_w - 32, color_dot=green)
    card(x + 410, y - 132, safe_w, 132, fill=light_red)
    set_font(13, bold=True, color=red)
    c.drawString(x + 426, y - 24, "Оставить локально")
    bullet_list(["исходные журналы и архивы", "сгенерированные HTML-отчеты", "EXE/ZIP с реальными результатами", "служебные временные папки"], x + 426, y - 50, safe_w - 32, color_dot=red)
    c.showPage()

    c.save()
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Russian EVTX Auditor PDF guide with WinAudit-like diagrams.")
    parser.add_argument("--output", default="docs/EVTXAuditor_User_Guide.pdf")
    args = parser.parse_args()
    path = build_pdf(args.output)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
