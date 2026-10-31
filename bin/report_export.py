"""Optional, local PDF export of the public management report (no network)."""
from __future__ import annotations
from pathlib import Path
import os
import tempfile


class PDFExportError(RuntimeError):
    """PDF export was requested but cannot be completed securely."""


def export_management_pdf(case: Path) -> Path:
    """Export only report.md; never include private technical evidence or secrets."""
    source = case / "report.md"
    output = case / "management-report.pdf"
    if source.is_symlink() or not source.is_file() or output.is_symlink():
        raise PDFExportError("Missing or unsafe management report source/destination")
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, KeepTogether
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.colors import HexColor
        from xml.sax.saxutils import escape
    except ImportError as error:
        raise PDFExportError("PDF export requires optional dependency: pip install reportlab") from error
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="FindingTitle", parent=styles["Heading3"],
                              textColor=HexColor("#26364D"), spaceBefore=11, spaceAfter=5))
    styles.add(ParagraphStyle(name="FindingText", parent=styles["BodyText"],
                              leading=15, spaceAfter=6, alignment=TA_LEFT, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="SmallEvidence", parent=styles["BodyText"],
                              fontSize=8, leading=11, spaceAfter=4, wordWrap="CJK"))
    elements = []
    import re
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            elements.append(Spacer(1, 5))
            continue
        depth = len(line) - len(line.lstrip("#"))
        if depth and depth <= 4 and len(line) > depth and line[depth] == " ":
            style = styles["Title"] if depth == 1 else styles["Heading2"] if depth == 2 else styles["FindingTitle"]
            line = line[depth + 1:]
        else:
            style = styles["FindingText"] if not line.startswith("- ") else styles["SmallEvidence"]
        # Render Markdown as plain text to avoid feeding attacker-controlled HTML to PDF parser.
        rendered = escape(re.sub(r"[*\x60]", "", line))
        elements.append(Paragraph(rendered, style))
    temporary = None
    with tempfile.NamedTemporaryFile(prefix=".management-report-", suffix=".pdf.tmp", dir=case, delete=False) as handle:
        temporary = Path(handle.name)
    doc = SimpleDocTemplate(str(temporary), pagesize=A4, rightMargin=43, leftMargin=43,
                            topMargin=55, bottomMargin=50,
                            title="WordPress Integrity Audit - Management Report")
    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(A4[0] - 43, 31, f"Page {document.page}")
        canvas.restoreState()
    try:
        doc.build(elements, onFirstPage=footer, onLaterPages=footer)
        if temporary.stat().st_size < 5 or not temporary.read_bytes()[:5] == b"%PDF-":
            raise PDFExportError("PDF renderer did not produce a valid PDF header")
        temporary.chmod(0o600)
        os.replace(temporary, output)
        return output
    except Exception as error:
        raise PDFExportError("PDF rendering failed; no completed PDF was published") from error
    finally:
        temporary.unlink(missing_ok=True)
