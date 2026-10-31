"""Exportação local opcional do relatório gerencial em PDF, sem acesso à rede."""
from __future__ import annotations
from pathlib import Path
import os
import tempfile


class PDFExportError(RuntimeError):
    """A exportação do PDF não pôde ser concluída com segurança."""


def export_management_pdf(case: Path) -> Path:
    """Exportar apenas report.md, sem evidências técnicas sigilosas ou credenciais."""
    source = case / "report.md"
    output = case / "management-report.pdf"
    if source.is_symlink() or not source.is_file() or output.is_symlink():
        raise PDFExportError("Origem ou destino do relatório gerencial ausente ou inseguro")
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, KeepTogether
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.colors import HexColor
        from xml.sax.saxutils import escape
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError as error:
        raise PDFExportError("A exportação para PDF exige a dependência opcional: pip install reportlab") from error
    # Preferir fontes Unicode normalmente disponíveis em Debian/Ubuntu.
    fonte = "Helvetica"
    alternativas = (
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"),
        Path("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"),
    )
    for arquivo_fonte in alternativas:
        if arquivo_fonte.is_file():
            try:
                pdfmetrics.registerFont(TTFont("FonteAuditoriaUnicode", str(arquivo_fonte)))
                fonte = "FonteAuditoriaUnicode"
                break
            except (OSError, ValueError):
                continue
    styles = getSampleStyleSheet()
    for nome in ("Normal", "BodyText", "Title", "Heading2", "Heading3"):
        styles[nome].fontName = fonte
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
                            title="Auditoria de Integridade WordPress - Relatório Gerencial")
    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont(fonte, 8)
        canvas.drawRightString(A4[0] - 43, 31, f"Página {document.page}")
        canvas.restoreState()
    try:
        doc.build(elements, onFirstPage=footer, onLaterPages=footer)
        with temporary.open("rb") as rendered:
            header = rendered.read(5)
        if header != b"%PDF-":
            raise PDFExportError("A geração não produziu um cabeçalho PDF válido")
        temporary.chmod(0o600)
        os.replace(temporary, output)
        return output
    except Exception as error:
        raise PDFExportError("Falha ao gerar PDF; nenhum documento incompleto foi publicado") from error
    finally:
        temporary.unlink(missing_ok=True)
