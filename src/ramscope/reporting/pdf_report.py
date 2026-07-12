from __future__ import annotations

from pathlib import Path


class PdfReport:
    def render(self, path: Path, title: str, markdown_text: str) -> Path:
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

        path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(str(path), pagesize=LETTER, title=title)
        styles = getSampleStyleSheet()
        story = [Paragraph(title, styles["Title"]), Spacer(1, 12)]
        for line in markdown_text.splitlines():
            if not line.strip():
                story.append(Spacer(1, 6))
                continue
            safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if safe.startswith("# "):
                story.append(Paragraph(safe[2:], styles["Heading1"]))
            elif safe.startswith("## "):
                story.append(Paragraph(safe[3:], styles["Heading2"]))
            elif safe.startswith("### "):
                story.append(Paragraph(safe[4:], styles["Heading3"]))
            elif safe.startswith("- "):
                story.append(Paragraph("• " + safe[2:], styles["BodyText"]))
            else:
                story.append(Paragraph(safe, styles["BodyText"]))
        doc.build(story)
        return path
