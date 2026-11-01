from __future__ import annotations

import json
import html
import hashlib
import mimetypes
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import traceback
import unicodedata
import uuid
from datetime import datetime
from pathlib import Path

import streamlit as st


APP_ROOT = Path(__file__).parent
# Keep runtime data in the PWS root even though the source code lives in the
# dedicated "AI-agent code" folder.
PROJECT_ROOT = APP_ROOT.parent if APP_ROOT.name.lower() == "ai-agent code" else APP_ROOT
DATA_ROOT = PROJECT_ROOT / "app_data"
FILES_ROOT = DATA_ROOT / "files"
STATE_FILE = DATA_ROOT / "state.json"
AGENT_PROMPT_FILE = APP_ROOT / "agent_prompt.txt"
BASE_DATA_ROOT = DATA_ROOT
SUPABASE_BUCKET = "lesmaat-files"
SUPABASE_ERROR = ""


def secret_value(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value
    try:
        return str(st.secrets.get(name, "")).strip()
    except Exception:
        return ""


@st.cache_resource(show_spinner=False)
def _cached_supabase_client(url: str, key: str):
    from supabase import create_client

    return create_client(url, key)


def supabase_client():
    """Create the server-only Supabase client when hosting secrets exist."""
    url = secret_value("SUPABASE_URL")
    key = secret_value("SUPABASE_SECRET_KEY") or secret_value("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        return None
    try:
        return _cached_supabase_client(url, key)
    except Exception:
        return None


def remote_file_path(file_info: dict) -> str:
    user_part = storage_safe_component(str(globals().get("current_user_id", "local_dev")))
    folder_part = storage_safe_component(str(file_info.get("folder", "root")))
    name_part = storage_safe_component(str(file_info.get("name", "bestand")))
    return f"{user_part}/{folder_part}/{name_part}"


def storage_safe_component(value: str) -> str:
    """Use an ASCII-safe object key while preserving the display filename."""
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", normalized).strip("._")
    return safe or "bestand"


def download_remote_files(state: dict, client) -> None:
    """Restore the user's files from private Supabase Storage to local cache."""
    if not client:
        return
    for file_info in state.get("files", []):
        local_path = FILES_ROOT / str(file_info.get("folder", "root")) / clean_name(str(file_info.get("name", "bestand")))
        local_path.parent.mkdir(parents=True, exist_ok=True)
        storage_path = file_info.get("remote_path") or remote_file_path(file_info)
        try:
            if not local_path.exists():
                content = client.storage.from_(SUPABASE_BUCKET).download(storage_path)
                local_path.write_bytes(content)
            file_info["path"] = str(local_path)
            file_info["remote_path"] = storage_path
            file_info["remote_size"] = local_path.stat().st_size
            file_info["remote_modified"] = local_path.stat().st_mtime
        except Exception:
            continue


def upload_state_files(state: dict, client) -> None:
    """Mirror current local files to the private Supabase bucket."""
    global SUPABASE_ERROR
    if not client:
        return
    for file_info in state.get("files", []):
        local_path = resolve_file_path(file_info)
        if not local_path:
            continue
        local_size = local_path.stat().st_size
        local_modified = local_path.stat().st_mtime
        if (
            file_info.get("remote_path")
            and file_info.get("remote_size") == local_size
            and file_info.get("remote_modified") == local_modified
        ):
            continue
        storage_path = file_info.get("remote_path") or remote_file_path(file_info)
        try:
            client.storage.from_(SUPABASE_BUCKET).upload(
                path=storage_path,
                file=local_path.read_bytes(),
                file_options={"cache-control": "3600", "upsert": "true", "content-type": file_mime_type(local_path)},
            )
            file_info["remote_path"] = storage_path
            file_info["remote_size"] = local_size
            file_info["remote_modified"] = local_modified
        except Exception as upload_exc:
            try:
                client.storage.from_(SUPABASE_BUCKET).update(
                    path=storage_path,
                    file=local_path.read_bytes(),
                    file_options={"cache-control": "3600", "content-type": file_mime_type(local_path)},
                )
                file_info["remote_path"] = storage_path
                file_info["remote_size"] = local_size
                file_info["remote_modified"] = local_modified
            except Exception as update_exc:
                SUPABASE_ERROR = f"Bestand '{local_path.name}' kon niet naar Supabase worden geüpload ({type(update_exc).__name__})."
                try:
                    (DATA_ROOT / "supabase_error.log").write_text(
                        f"Uploadfout:\n{upload_exc}\n\nUpdatefout:\n{traceback.format_exc()}",
                        encoding="utf-8",
                    )
                except OSError:
                    pass
                continue


def delete_remote_file(file_info: dict, storage_path: str | None = None) -> None:
    """Remove an obsolete object from the user's private Supabase folder."""
    client = supabase_client() if globals().get("current_user_id") != "local_dev" else None
    if not client:
        return
    path = storage_path or file_info.get("remote_path") or remote_file_path(file_info)
    try:
        client.storage.from_(SUPABASE_BUCKET).remove([path])
    except Exception:
        try:
            (DATA_ROOT / "supabase_error.log").write_text(traceback.format_exc(), encoding="utf-8")
        except OSError:
            pass


def configured_users() -> dict:
    """Read hashed user records from an environment secret.

    Authentication is enabled when LESMAAT_USERS_JSON is present. Keeping the
    records outside the repository prevents passwords from entering GitHub.
    """
    raw = os.environ.get("LESMAAT_USERS_JSON", "").strip()
    if not raw:
        local_users_file = APP_ROOT / "users.local.json"
        if local_users_file.exists():
            try:
                parsed = json.loads(local_users_file.read_text(encoding="utf-8"))
                return parsed if isinstance(parsed, dict) else {}
            except (json.JSONDecodeError, OSError):
                return {}
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def verify_user_password(password: str, record: dict) -> bool:
    try:
        salt = bytes.fromhex(str(record["salt"]))
        expected = bytes.fromhex(str(record["hash"]))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180_000)
        return secrets.compare_digest(actual, expected)
    except (KeyError, TypeError, ValueError):
        return False


def authenticate_user() -> str | None:
    """Return the logged-in user id, or show the login form and stop."""
    users = configured_users()
    if not users:
        # Local development remains frictionless until hosting secrets are set.
        return "local_dev"
    if st.session_state.get("authenticated_user") in users:
        return st.session_state["authenticated_user"]
    st.markdown('<div class="hero"><h1>Inloggen bij SocrAItes</h1><p>Gebruik je persoonlijke docentaccount.</p></div>', unsafe_allow_html=True)
    with st.form("login_form"):
        username = st.text_input("Gebruikersnaam")
        password = st.text_input("Wachtwoord", type="password")
        submitted = st.form_submit_button("Inloggen", type="primary")
    if submitted:
        record = users.get(username.strip())
        if isinstance(record, dict) and verify_user_password(password, record):
            st.session_state["authenticated_user"] = username.strip()
            st.rerun()
        st.error("De gebruikersnaam of het wachtwoord klopt niet.")
    st.stop()


def now_label() -> str:
    return datetime.now().strftime("%d-%m-%Y %H:%M")


def clean_name(name: str) -> str:
    safe = re.sub(r"[^\w.() -]", "_", Path(name).name, flags=re.UNICODE).strip()
    return safe or "bestand"


def file_icon(name: str) -> str:
    suffix = Path(name).suffix.lower()
    return {".pptx": "📊", ".ppt": "📊", ".pdf": "📕", ".docx": "📝", ".doc": "📝", ".txt": "📄", ".md": "📄", ".png": "🖼️", ".jpg": "🖼️", ".jpeg": "🖼️"}.get(suffix, "📄")


def open_external(path: str) -> bool:
    """Open a local file with the operating system's default application."""
    file_path = Path(path)
    if not file_path.exists():
        return False
    try:
        if os.name == "nt":
            os.startfile(str(file_path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(file_path)])
        else:
            subprocess.Popen(["xdg-open", str(file_path)])
        return True
    except OSError:
        return False


def resolve_file_path(file_info: dict) -> Path | None:
    """Find a stored file even when its saved absolute path became stale."""
    candidates = []
    saved_path = file_info.get("path")
    if saved_path:
        candidates.append(Path(saved_path))
    folder = file_info.get("folder", "root")
    name = file_info.get("name", "")
    if name:
        candidates.append(FILES_ROOT / folder / name)
        candidates.extend(FILES_ROOT.rglob(name))
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    # A hosted app may have lost its local cache after a restart. Restore the
    # requested file lazily from private Supabase Storage when possible.
    client = supabase_client() if globals().get("current_user_id") != "local_dev" else None
    if client and name:
        restored_path = FILES_ROOT / str(folder) / clean_name(str(name))
        storage_path = file_info.get("remote_path") or remote_file_path(file_info)
        try:
            restored_path.parent.mkdir(parents=True, exist_ok=True)
            restored_path.write_bytes(client.storage.from_(SUPABASE_BUCKET).download(storage_path))
            file_info["path"] = str(restored_path)
            file_info["remote_path"] = storage_path
            return restored_path
        except Exception:
            return None
    return None


def file_mime_type(path: Path) -> str:
    """Return a useful MIME type for browser downloads."""
    return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def requests_pdf_output(prompt: str) -> bool:
    text = prompt.lower()
    return any(word in text for word in ("pdf", "hand-out", "handout", "werkblad", "printbare"))


def document_body_from_answer(answer: str) -> str:
    """Remove chat-only framing before turning an AI answer into a document."""
    text = answer.replace("\r\n", "\n").strip()
    marker_pairs = (("[DOCUMENT_BEGIN]", "[DOCUMENT_END]"), ("<DOCUMENT_BEGIN>", "<DOCUMENT_END>"))
    for start_marker, end_marker in marker_pairs:
        if start_marker in text:
            text = text.split(start_marker, 1)[1]
            if end_marker in text:
                text = text.split(end_marker, 1)[0]
            return text.strip()

    # The model sometimes adds a short conversational introduction. Remove only
    # clearly meta lines and keep the first actual lesson paragraph intact.
    lines = text.splitlines()
    meta_prefixes = (
        "hier is de gevraagde",
        "hieronder staat de gevraagde",
        "natuurlijk, hier",
        "je vroeg om",
        "je hebt gevraagd om",
        "ik stel voor",
        "ik maak voor je",
        "rollen:",
        "de beschikbare bestanden",
    )
    while lines:
        first = lines[0].strip().lower()
        if not first:
            lines.pop(0)
            continue
        if first in {"document:", "leshand-out:", "leshandout:", "inhoud:", "antwoord:", "ai-response:", "ai-antwoord:", "hier is de leshand-out:", "hier is de hand-out:"}:
            lines.pop(0)
            continue
        if first.startswith(meta_prefixes):
            lines.pop(0)
            continue
        break
    return normalize_document_markup("\n".join(lines).strip())


def normalize_document_markup(text: str) -> str:
    """Turn common LaTeX snippets from AI output into readable document text."""
    text = text.replace("\\(", "").replace("\\)", "")
    text = text.replace("\\[", "").replace("\\]", "")
    text = re.sub(r"\\text\{([^{}]*)\}", r"\1", text)
    # Convert simple fractions to readable linear notation instead of leaving
    # raw LaTeX commands in generated documents.
    fraction_pattern = re.compile(r"\\frac\{([^{}]*)\}\{([^{}]*)\}")
    while fraction_pattern.search(text):
        text = fraction_pattern.sub(r"(\1)/(\2)", text)
    text = re.sub(r"\\begin\{cases\}|\\end\{cases\}", "", text)
    text = text.replace("\\\\", " ; ")
    replacements = {
        r"\leq": "≤",
        r"\geq": "≥",
        r"\times": "×",
        r"\cdot": "·",
        r"\rightarrow": "->",
        r"\qquad": " ",
        r"\quad": " ",
        r"\cdots": "...",
        r"\,": " ",
        r"\;": " ",
    }
    for source, replacement in replacements.items():
        text = text.replace(source, replacement)
    sqrt_pattern = re.compile(r"\\sqrt\{([^{}]*)\}")
    while sqrt_pattern.search(text):
        text = sqrt_pattern.sub(r"√(\1)", text)
    text = re.sub(r"\\int_", "∫_", text)
    text = text.replace(r"\infty", "∞").replace(r"\pi", "π").replace(r"\neq", "≠")
    # Keep generated documents readable even when the model returns Unicode
    # math symbols that are missing from the selected PDF font.
    unicode_math_replacements = {
        "−": "-",
        "—": "-",
        "–": "-",
        "→": "→",
    }
    for source, replacement in unicode_math_replacements.items():
        text = text.replace(source, replacement)
    text = re.sub(r"\\int_([^\s]+)\^([^\s]+)", r"integral_\1^\2", text)
    text = text.replace(r"\ ", " ")
    text = re.sub(r"\^\{([^{}]*)\}", r"^\1", text)
    text = text.replace(r"\left", "").replace(r"\right", "")
    text = text.replace("{", "").replace("}", "")
    text = text.replace("–", "-").replace("—", "-").replace("•", "-").replace("→", "->")
    cleaned_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]") and ("integral" in stripped or "=" in stripped):
            leading = line[: len(line) - len(line.lstrip())]
            line = leading + stripped[1:-1].strip()
        cleaned_lines.append(line)
    text = "\n".join(cleaned_lines)
    return text


def normalize_chat_math(text: str) -> str:
    """Make bracketed LaTeX formulas render as math in Streamlit chat."""
    text = text.replace("\\[", "$$").replace("\\]", "$$")
    text = text.replace("\\(", "$").replace("\\)", "$")
    lines = text.replace("\r\n", "\n").splitlines()
    normalized = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]") and "\\" in stripped:
            normalized.extend(["$$", stripped[1:-1].strip(), "$$"])
        else:
            normalized.append(line)
    return "\n".join(normalized)


def register_pdf_fonts():
    """Register a Unicode-capable font so arrows and tree characters render."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    candidates = []
    try:
        from matplotlib.font_manager import findfont

        dejavu_regular = findfont("DejaVu Sans")
        dejavu_bold = findfont("DejaVu Sans:style=bold")
        dejavu_italic = findfont("DejaVu Sans:style=italic")
        dejavu_bold_italic = findfont("DejaVu Sans:style=bold italic")
        candidates.append(("SocrAItesSans", dejavu_regular, dejavu_bold, dejavu_italic, dejavu_bold_italic))
    except Exception:
        pass
    candidates.extend([
        ("LesmaatSans", "C:\\Windows\\Fonts\\arial.ttf", "C:\\Windows\\Fonts\\arialbd.ttf", "C:\\Windows\\Fonts\\ariali.ttf", "C:\\Windows\\Fonts\\arialbi.ttf"),
        ("LesmaatSans", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-BoldOblique.ttf"),
    ])
    for family, regular, bold, italic, bold_italic in candidates:
        if all(Path(path).exists() for path in (regular, bold, italic, bold_italic)):
            try:
                if family in pdfmetrics.getRegisteredFontNames():
                    return family
                pdfmetrics.registerFont(TTFont(family, regular))
                pdfmetrics.registerFont(TTFont(f"{family}-Bold", bold))
                pdfmetrics.registerFont(TTFont(f"{family}-Italic", italic))
                pdfmetrics.registerFont(TTFont(f"{family}-BoldItalic", bold_italic))
                pdfmetrics.registerFontFamily(family, normal=family, bold=f"{family}-Bold", italic=f"{family}-Italic", boldItalic=f"{family}-BoldItalic")
                return family
            except Exception:
                continue
    return "Helvetica"


def pdf_inline_markup(text: str) -> str:
    """Convert the small Markdown subset used by the agent to ReportLab XML."""
    escaped = html.escape(text, quote=False)
    escaped = re.sub(r"`([^`]+)`", r"<font name=\"Courier\">\1</font>", escaped)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"__(.+?)__", r"<b>\1</b>", escaped)
    escaped = re.sub(r"(?<!\*)\*([^*\n]+?)\*(?!\*)", r"<i>\1</i>", escaped)
    return escaped


def markdown_plain_text(text: str) -> str:
    """Remove Markdown markers for formats that do not support rich text cells."""
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"__(.+?)__", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    return normalize_document_markup(re.sub(r"(?<!\*)\*([^*\n]+?)\*(?!\*)", r"\1", text))


def add_docx_markdown_paragraph(document, text: str, style: str | None = None):
    """Add a Word paragraph while converting the supported Markdown emphasis."""
    paragraph = document.add_paragraph(style=style)
    tokens = re.split(r"(\*\*.+?\*\*|__.+?__|`[^`]+`|(?<!\*)\*[^*\n]+?\*(?!\*))", text)
    for token in tokens:
        if not token:
            continue
        run = paragraph.add_run(markdown_plain_text(token))
        if (token.startswith("**") and token.endswith("**")) or (token.startswith("__") and token.endswith("__")):
            run.bold = True
        elif token.startswith("*") and token.endswith("*"):
            run.italic = True
        elif token.startswith("`") and token.endswith("`"):
            run.font.name = "Courier New"
    return paragraph


def add_pptx_markdown_runs(paragraph, text: str, font_size):
    tokens = re.split(r"(\*\*.+?\*\*|__.+?__|`[^`]+`|(?<!\*)\*[^*\n]+?\*(?!\*))", text)
    for token in tokens:
        if not token:
            continue
        run = paragraph.add_run()
        run.text = markdown_plain_text(token)
        run.font.name = "Arial"
        run.font.size = font_size
        if (token.startswith("**") and token.endswith("**")) or (token.startswith("__") and token.endswith("__")):
            run.font.bold = True
        elif token.startswith("*") and token.endswith("*"):
            run.font.italic = True


def set_pptx_markdown_text(text_frame, text: str, font_size):
    """Write basic Markdown emphasis as formatted PowerPoint runs."""
    text_frame.clear()
    lines = text.splitlines() or [""]
    for line_index, line in enumerate(lines):
        paragraph = text_frame.paragraphs[0] if line_index == 0 else text_frame.add_paragraph()
        add_pptx_markdown_runs(paragraph, line, font_size)


def render_function_graphs(graph_specs: list[dict] | None) -> list[Path]:
    """Render safe, simple function plots locally from the AI's graph metadata."""
    if not isinstance(graph_specs, list):
        return []
    rendered: list[Path] = []
    try:
        import numpy as np
        import sympy as sp
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return []
    allowed_names = {"x": sp.Symbol("x"), "sqrt": sp.sqrt, "exp": sp.exp, "sin": sp.sin, "cos": sp.cos, "tan": sp.tan, "log": sp.log, "pi": sp.pi, "E": sp.E}
    safe_pattern = re.compile(r"^[0-9A-Za-z_xX+*/().,^ -]+$")
    for index, spec in enumerate(graph_specs[:3], start=1):
        if not isinstance(spec, dict) or spec.get("requested") is False:
            continue
        functions = spec.get("functions") or []
        domain = spec.get("domain") or {}
        if not isinstance(functions, list) or not functions or not isinstance(domain, dict):
            continue
        try:
            x_min = float(domain.get("min"))
            x_max = float(domain.get("max"))
            if not x_max > x_min or x_max - x_min > 10000:
                continue
            x_symbol = allowed_names["x"]
            x_values = np.linspace(x_min, x_max, 600)
            curves = []
            for function in functions[:4]:
                expression = str(function.get("expression", "")).replace("^", "**")
                if not expression or not safe_pattern.fullmatch(expression):
                    raise ValueError("onveilige grafiekexpressie")
                expression_obj = sp.sympify(expression, locals=allowed_names)
                evaluator = sp.lambdify(x_symbol, expression_obj, modules=["numpy"])
                y_values = np.asarray(evaluator(x_values), dtype=float)
                if y_values.shape == ():
                    y_values = np.full_like(x_values, float(y_values))
                y_values = np.where(np.isfinite(y_values), y_values, np.nan)
                curves.append((function, y_values))
            figure, axis = plt.subplots(figsize=(7.4, 4.4), dpi=150)
            for function, y_values in curves:
                label = str(function.get("label", "")).strip() or None
                axis.plot(x_values, y_values, linewidth=2, label=label)
            if len(curves) >= 2 and spec.get("shade_between"):
                axis.fill_between(x_values, curves[0][1], curves[1][1], color="#7aa2f7", alpha=0.22)
            for point in spec.get("points", [])[:12]:
                match = re.fullmatch(r"\s*\(?\s*(-?[0-9]+(?:[.,][0-9]+)?)\s*,\s*(-?[0-9]+(?:[.,][0-9]+)?)\s*\)?\s*", str(point))
                if match:
                    px, py = (float(value.replace(",", ".")) for value in match.groups())
                    axis.scatter([px], [py], color="#d64545", zorder=4)
                    axis.annotate(f"({px:g}, {py:g})", (px, py), xytext=(5, 5), textcoords="offset points", fontsize=8)
            axis.axhline(0, color="#667085", linewidth=0.8)
            axis.axvline(0, color="#667085", linewidth=0.8)
            axis.grid(True, alpha=0.25)
            axis.set_xlabel(str(spec.get("x_label", domain.get("variable", "x"))))
            axis.set_ylabel(str(spec.get("y_label", "y")))
            if spec.get("title"):
                axis.set_title(str(spec["title"]))
            if any(item.get("label") for item, _ in curves):
                axis.legend()
            figure.tight_layout()
            output_path = Path(tempfile.gettempdir()) / f"lesmaat_graph_{uuid.uuid4().hex}_{index}.png"
            figure.savefig(output_path, bbox_inches="tight")
            plt.close(figure)
            rendered.append(output_path)
        except Exception:
            continue
    return rendered


def create_pdf_from_text(title: str, content: str, state: dict, graph_specs: list[dict] | None = None) -> dict | None:
    """Create a simple, printable PDF from the AI's hand-out text."""
    try:
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer

        content = document_body_from_answer(content)
        font_family = register_pdf_fonts()
        output_name = f"{clean_name(title)[:60]}_{datetime.now().strftime('%H%M%S')}.pdf"
        temporary_path = Path(tempfile.gettempdir()) / clean_name(output_name)
        styles = getSampleStyleSheet()
        body_style = ParagraphStyle("HandoutBody", parent=styles["BodyText"], fontName=font_family, fontSize=10.5, leading=15, alignment=TA_LEFT, spaceAfter=7)
        heading_style = ParagraphStyle("HandoutHeading", parent=styles["Heading2"], fontName=f"{font_family}-Bold" if font_family != "Helvetica" else "Helvetica-Bold", fontSize=14, leading=18, spaceBefore=10, spaceAfter=6)
        document = SimpleDocTemplate(str(temporary_path), pagesize=A4, rightMargin=2 * cm, leftMargin=2 * cm, topMargin=1.8 * cm, bottomMargin=1.8 * cm)
        title_style = ParagraphStyle("HandoutTitle", parent=styles["Title"], fontName=f"{font_family}-Bold" if font_family != "Helvetica" else "Helvetica-Bold")
        story = [Paragraph(pdf_inline_markup(title), title_style), Spacer(1, 10)]
        for raw_line in content.splitlines():
            line = raw_line.rstrip()
            if not line:
                story.append(Spacer(1, 5))
            elif line.startswith("#"):
                story.append(Paragraph(pdf_inline_markup(line.lstrip("# ")), heading_style))
            elif line.startswith(("- ", "* ")):
                story.append(Paragraph("&bull; " + pdf_inline_markup(line[2:]), body_style))
            else:
                story.append(Paragraph(pdf_inline_markup(line), body_style))
        graph_paths = render_function_graphs(graph_specs)
        for graph_path in graph_paths:
            story.extend([Spacer(1, 8), Image(str(graph_path), width=16 * cm, height=9.5 * cm), Spacer(1, 8)])
        document.build(story)
        for graph_path in graph_paths:
            graph_path.unlink(missing_ok=True)
        generated = store_file_bytes(state, "root", output_name, temporary_path.read_bytes())
        temporary_path.unlink(missing_ok=True)
        return generated
    except Exception:
        try:
            (DATA_ROOT / "pdf_error.log").write_text(traceback.format_exc(), encoding="utf-8")
        except OSError:
            pass
        return None


def create_docx_from_text(title: str, content: str, state: dict, graph_specs: list[dict] | None = None) -> dict | None:
    try:
        from docx import Document
        from docx.shared import Inches

        content = document_body_from_answer(content)
        output_name = f"{clean_name(title)[:60]}_{datetime.now().strftime('%H%M%S')}.docx"
        temporary_path = Path(tempfile.gettempdir()) / clean_name(output_name)
        document = Document()
        document.add_heading(title, level=0)
        for raw_line in content.splitlines():
            line = raw_line.rstrip()
            if not line:
                continue
            if line.startswith("#"):
                document.add_heading(markdown_plain_text(line.lstrip("# ")), level=1)
            elif line.startswith(("- ", "* ")):
                add_docx_markdown_paragraph(document, line[2:], style="List Bullet")
            else:
                add_docx_markdown_paragraph(document, line)
        graph_paths = render_function_graphs(graph_specs)
        for graph_path in graph_paths:
            document.add_picture(str(graph_path), width=Inches(6.2))
            graph_path.unlink(missing_ok=True)
        document.save(str(temporary_path))
        generated = store_file_bytes(state, "root", output_name, temporary_path.read_bytes())
        temporary_path.unlink(missing_ok=True)
        return generated
    except Exception:
        return None


def create_xlsx_from_text(title: str, content: str, state: dict) -> dict | None:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font

        content = document_body_from_answer(content)
        output_name = f"{clean_name(title)[:60]}_{datetime.now().strftime('%H%M%S')}.xlsx"
        temporary_path = Path(tempfile.gettempdir()) / clean_name(output_name)
        workbook = Workbook()
        worksheet = workbook.active
        worksheet.title = "Lesmateriaal"
        worksheet.append([title])
        worksheet["A1"].font = Font(bold=True, size=14)
        for raw_line in content.splitlines():
            line = raw_line.rstrip()
            if line:
                value = line[2:] if line.startswith(("- ", "* ")) else line
                worksheet.append([markdown_plain_text(value.lstrip("# ") if line.startswith("#") else value)])
                if line.startswith("#"):
                    worksheet.cell(worksheet.max_row, 1).font = Font(bold=True, size=12)
        workbook.save(str(temporary_path))
        generated = store_file_bytes(state, "root", output_name, temporary_path.read_bytes())
        temporary_path.unlink(missing_ok=True)
        return generated
    except Exception:
        return None


def requested_output_type(prompt: str, history: list[dict] | None = None, chat_context: dict | None = None) -> str | None:
    text = prompt.lower()
    if requests_pdf_output(prompt):
        return "pdf"
    if any(word in text for word in ("word", "docx", "document")):
        return "docx"
    if any(word in text for word in ("excel", "xlsx", "spreadsheet", "rekenblad")):
        return "xlsx"
    return None


def ai_requested_hard_stop(answer: str) -> bool:
    """Detect explicit stop language before any file-producing follow-up runs."""
    normalized = answer.lower().replace("–", "-").replace("—", "-")
    markers = (
        "hard stop",
        "harde stop",
        "geen relevante informatie gevonden",
        "niet betrouwbaar kan worden uitgevoerd",
        "nog niet betrouwbaar uitvoeren",
        "wacht op een nieuwe instructie",
    )
    return any(marker in normalized[:2500] for marker in markers)


def ai_request_failed(answer: str) -> bool:
    """Detect a failed model request so the workflow trace does not claim success."""
    normalized = answer.lower()
    return "de ai-aanvraag is mislukt" in normalized or "authenticationerror" in normalized or "authentication error" in normalized


def powerpoint_snapshot(path: Path) -> tuple[Path | None, Path | None]:
    """Return a readable copy when PowerPoint has the source file locked."""
    if os.name == "nt":
        # OneDrive Files On-Demand can expose a path that is not readable by
        # Python yet. Pin the file locally and give OneDrive a moment to
        # hydrate it before falling back to PowerPoint's COM copy mechanism.
        try:
            subprocess.run(["attrib", "-U", "+P", str(path)], capture_output=True, check=False)
        except OSError:
            pass
    try:
        with path.open("rb"):
            return path, None
    except PermissionError:
        for _ in range(10):
            time.sleep(0.5)
            try:
                with path.open("rb"):
                    return path, None
            except PermissionError:
                continue
        if os.name != "nt":
            return None, None
    try:
        import win32com.client

        powerpoint = win32com.client.GetActiveObject("PowerPoint.Application")
        wanted = os.path.normcase(os.path.abspath(str(path)))
        for presentation in powerpoint.Presentations:
            try:
                current = os.path.normcase(os.path.abspath(str(presentation.FullName)))
            except Exception:
                continue
            if current == wanted:
                snapshot = Path(tempfile.gettempdir()) / f"lesmaat_snapshot_{uuid.uuid4().hex}.pptx"
                presentation.SaveCopyAs(str(snapshot))
                return snapshot, snapshot
    except Exception:
        return None, None
    return None, None


def store_file_bytes(state: dict, folder_id: str, name: str, content: bytes) -> dict:
    """Persist an uploaded/generated file and register it in the library.

    The future AI layer can use this same function for an edited PowerPoint,
    ensuring that the result is both saved locally and downloadable.
    """
    safe_name = clean_name(name)
    target = FILES_ROOT / folder_id
    target.mkdir(parents=True, exist_ok=True)
    path = target / safe_name
    path.write_bytes(content)
    info = {
        "id": str(uuid.uuid4()),
        "name": safe_name,
        "folder": folder_id,
        "path": str(path),
        "size": path.stat().st_size,
        "added": now_label(),
        "modified": path.stat().st_mtime,
    }
    state["files"].append(info)
    return info


def load_agent_prompt() -> str:
    """Load the editable agent instructions from the project folder."""
    try:
        return AGENT_PROMPT_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return "Je bent een behulpzame Nederlandstalige onderwijsassistent."


def extract_file_text(path: Path) -> str:
    """Extract useful text locally before sending context to the model."""
    suffix = path.suffix.lower()
    try:
        if suffix in {".txt", ".md"}:
            return path.read_text(encoding="utf-8", errors="ignore")
        if suffix == ".docx":
            from docx import Document

            document = Document(str(path))
            return "\n".join(paragraph.text for paragraph in document.paragraphs if paragraph.text.strip())
        if suffix == ".pptx":
            from pptx import Presentation

            readable_path, temporary_path = powerpoint_snapshot(path)
            if not readable_path:
                return "[DIT BESTAND KAN NIET WORDEN GELEZEN: sluit PowerPoint niet; de app kon geen tijdelijke kopie maken. Controleer of PowerPoint actief is en probeer opnieuw.]"
            presentation = Presentation(str(readable_path))
            slides = []
            for number, slide in enumerate(presentation.slides, start=1):
                texts = [shape.text for shape in slide.shapes if hasattr(shape, "text") and shape.text.strip()]
                if texts:
                    slides.append(f"Dia {number}:\n" + "\n".join(texts))
            if temporary_path:
                temporary_path.unlink(missing_ok=True)
            if slides:
                return "\n\n".join(slides)
            return f"[PowerPoint gelezen: {len(presentation.slides)} dia('s), maar er staat geen uitleesbare tekst in.]"
        if suffix == ".pdf":
            from pypdf import PdfReader

            return "\n\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
        if suffix == ".xlsx":
            from openpyxl import load_workbook

            workbook = load_workbook(str(path), read_only=True, data_only=True)
            sheets = []
            for worksheet in workbook.worksheets:
                rows = []
                for row in worksheet.iter_rows(values_only=True):
                    values = [str(value) for value in row if value is not None]
                    if values:
                        rows.append(" | ".join(values))
                if rows:
                    sheets.append(f"Werkblad {worksheet.title}:\n" + "\n".join(rows[:500]))
            workbook.close()
            return "\n\n".join(sheets) or "[Excel-bestand gelezen, maar het bevat geen ingevulde cellen.]"
    except PermissionError:
        return "[DIT BESTAND KAN NIET WORDEN GELEZEN: het bestand is lokaal vergrendeld. Sluit PowerPoint en probeer opnieuw.]"
    except Exception as exc:
        return f"[DIT BESTAND KON NIET WORDEN UITGELEZEN ({type(exc).__name__}). Vraag de gebruiker om het bestand opnieuw te uploaden.]"
    return ""


def ask_agent(
    prompt: str,
    history: list[dict],
    file_paths: list[Path],
    settings: dict | None = None,
    library_paths: list[Path] | None = None,
    chat_context: dict | None = None,
) -> dict:
    """Ask once for both the visible answer and the updated chat context."""
    api_key = secret_value("OPENAI_API_KEY")
    if not api_key:
        return {"answer": "De API-key is niet gevonden. Stel OPENAI_API_KEY in en start de app opnieuw.", "chat_title": "", "context": None, "document": None, "action": None, "roles": None, "validation": None, "graphs": None}
    try:
        from openai import OpenAI

        context_parts = []
        seen_paths = set()
        context_chars = 0
        all_paths = list(file_paths) + list(library_paths or [])
        for path in all_paths:
            path = Path(path)
            if path in seen_paths or not path.exists():
                continue
            seen_paths.add(path)
            extracted = extract_file_text(path)
            if extracted:
                remaining = 120000 - context_chars
                if remaining <= 0:
                    break
                extracted = extracted[: min(40000, remaining)]
                source_label = "CHATBIJLAGE" if path in file_paths else "BESTANDSBIBLIOTHEEK"
                context_parts.append(f"{source_label}: {path.name}\n{extracted}")
                context_chars += len(extracted)
            else:
                context_parts.append(f"BESTAND: {path.name}\n(De tekst kon lokaal niet worden uitgelezen.)")
        recent_history = history[-8:]
        conversation = "\n".join(
            f"{item.get('role', 'user').upper()}: {item.get('content', '')}" for item in recent_history
        )
        profile = settings or {}
        profile_text = (
            f"Vak: {profile.get('subject') or 'onbekend'}\n"
            f"Niveau/leerjaar: {profile.get('level') or 'onbekend'}\n"
            f"Methode: {profile.get('method') or 'niet opgegeven'}\n"
            f"Lesaanpak: {profile.get('teaching_style') or 'niet opgegeven'}\n"
            f"Extra voorkeuren: {profile.get('extra') or 'geen'}"
        )
        input_text = (
            f"{load_agent_prompt()}\n\n"
            "Gebruik onderstaande chatgeschiedenis en bestanden als context. "
            "Beantwoord de nieuwste vraag in duidelijk Nederlands. Scheid het antwoord aan de docent van de inhoud van een eventueel bestand. "
            "Zet in document.content uitsluitend de inhoud die in het bestand moet komen; zet daar geen rolbeschrijving, bronnen, aannames of chatuitleg in. "
            "Als de docent bijvoorbeeld alleen opdrachten vraagt, bevat document.content alleen de leerlingopdracht met noodzakelijke context. "
            "Als geen bestand gevraagd wordt, gebruik requested=false en een lege document.content. "
            "Bepaal daarnaast de uit te voeren actie op basis van de volledige context: answer_only, create_document of edit_powerpoint. "
            "Gebruik edit_powerpoint uitsluitend als de nieuwste gebruikersvraag expliciet om een PowerPoint-bewerking vraagt; oude context of een aanwezig PowerPoint-bestand is daarvoor nooit voldoende. "
            "Geef bij edit_powerpoint alleen het exacte relevante doelbestand terug. Gebruik bij create_document het juiste output_type en laat Python die actie uitvoeren. Gebruik geen aannames buiten de context.\n\n"
            "Kies in dezelfde respons de rollen die werkelijk nodig zijn, in de juiste volgorde. Gebruik alleen deze rolbenamingen: Bestandenlezer, Actualiteitzoeker, Opdrachtmaker, Documentmaker, PowerPoint-bewerker en Lesvoorbereider. Neem een rol alleen op als die voor deze vraag nodig is. Geef ook een korte logische chat_title van maximaal vijf woorden, zonder aanhalingstekens of punt aan het einde.\n\n"
            "Controleer vóór documentgeneratie het niveau, de methode en de syllabus. Geef in validation status approved, blocked of needs_information. Gebruik blocked als de opdracht buiten de lesstof valt en needs_information als controle niet mogelijk is.\n\n"
            f"DOCENTPROFIEL:\n{profile_text}\n\n"
            f"VASTGELEGDE CHATCONTEXT:\n{json.dumps(chat_context or {}, ensure_ascii=False, indent=2)}\n\n"
            f"CHATGESCHIEDENIS:\n{conversation}\n\n"
            f"BIJGEVOEGDE BESTANDEN:\n{'\n\n'.join(context_parts) if context_parts else '(geen bestanden)'}\n\n"
            f"NIEUWSTE VRAAG:\n{prompt}"
        )
        client = OpenAI(api_key=api_key)
        context_schema = {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "active_task": {"type": "string"},
                "output_type": {"type": "string", "enum": ["none", "pdf", "docx", "xlsx", "pptx"]},
                "source_files": {"type": "array", "items": {"type": "string"}},
                "pending_actions": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary", "active_task", "output_type", "source_files", "pending_actions"],
            "additionalProperties": False,
        }
        response_schema = {
            "type": "object",
            "properties": {
                "answer": {"type": "string"},
                "chat_title": {"type": "string"},
                "context": context_schema,
                "document": {
                    "type": "object",
                    "properties": {
                        "requested": {"type": "boolean"},
                        "title": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["requested", "title", "content"],
                    "additionalProperties": False,
                },
                "action": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["answer_only", "create_document", "edit_powerpoint"]},
                        "output_type": {"type": "string", "enum": ["none", "pdf", "docx", "xlsx", "pptx"]},
                        "user_requested": {"type": "boolean"},
                        "target_files": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["kind", "output_type", "user_requested", "target_files"],
                    "additionalProperties": False,
                },
                "roles": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "role": {"type": "string", "enum": ["Bestandenlezer", "Actualiteitzoeker", "Opdrachtmaker", "Documentmaker", "PowerPoint-bewerker", "Lesvoorbereider"]},
                            "task": {"type": "string"},
                        },
                        "required": ["role", "task"],
                        "additionalProperties": False,
                    },
                },
                "validation": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "enum": ["approved", "blocked", "needs_information"]},
                        "reasons": {"type": "array", "items": {"type": "string"}},
                        "sources": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["status", "reasons", "sources"],
                    "additionalProperties": False,
                },
                "graphs": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "requested": {"type": "boolean"},
                            "type": {"type": "string", "enum": ["function_plot"]},
                            "functions": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {"expression": {"type": "string"}, "label": {"type": "string"}},
                                    "required": ["expression", "label"],
                                    "additionalProperties": False,
                                },
                            },
                            "domain": {
                                "type": "object",
                                "properties": {"variable": {"type": "string"}, "min": {"type": "number"}, "max": {"type": "number"}},
                                "required": ["variable", "min", "max"],
                                "additionalProperties": False,
                            },
                            "points": {"type": "array", "items": {"type": "string"}},
                            "shade_between": {"type": "boolean"},
                            "x_label": {"type": "string"},
                            "y_label": {"type": "string"},
                            "title": {"type": "string"},
                            "slide": {"type": "integer", "minimum": 1},
                        },
                        "required": ["requested", "type", "functions", "domain", "points", "shade_between", "x_label", "y_label", "title", "slide"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["answer", "chat_title", "context", "document", "action", "roles", "validation", "graphs"],
            "additionalProperties": False,
        }
        request = {
            "model": os.environ.get("OPENAI_MODEL", "gpt-6-luna"),
            "input": input_text + "\n\nGeef je antwoord en de bijgewerkte chatcontext terug volgens het opgegeven JSON-schema. Zet geen uitleg buiten het JSON-object.",
            "tools": [{"type": "web_search"}],
            "text": {"format": {"type": "json_schema", "name": "agent_answer_with_context", "strict": True, "schema": response_schema}},
        }
        try:
            response = client.responses.create(**request)
        except AttributeError:
            # Older SDK/API combinations can fail while serializing the newer
            # web search tool. Try the compatible preview name first.
            request["tools"] = [{"type": "web_search_preview"}]
            try:
                response = client.responses.create(**request)
            except AttributeError:
                # A normal response still keeps the chat usable when neither
                # search tool is available for the selected model.
                request.pop("tools", None)
                response = client.responses.create(**request)
        except Exception as exc:
            if type(exc).__name__ == "AuthenticationError":
                raise
            # Keep the normal answer usable for SDK/model combinations that do
            # not support structured output. This is only a failure fallback.
            request.pop("text", None)
            response = client.responses.create(**request)
        try:
            output_text = response.output_text
        except AttributeError:
            output_text = ""
            for output in getattr(response, "output", []) or []:
                for content in getattr(output, "content", []) or []:
                    text = getattr(content, "text", None)
                    if text:
                        output_text += text
        output_text = (output_text or "").strip()
        try:
            structured = json.loads(output_text)
        except json.JSONDecodeError:
            structured = None
        if isinstance(structured, dict) and isinstance(structured.get("answer"), str):
            return {
                "answer": structured["answer"].strip(),
                "chat_title": structured.get("chat_title", "").strip(),
                "context": structured.get("context"),
                "document": structured.get("document"),
                "action": structured.get("action"),
                "roles": structured.get("roles"),
                "validation": structured.get("validation"),
                "graphs": structured.get("graphs"),
            }
        return {"answer": output_text or "De AI gaf geen tekstueel antwoord terug.", "chat_title": "", "context": None, "document": None, "action": None, "roles": None, "validation": None, "graphs": None}
    except Exception as exc:
        try:
            (DATA_ROOT / "ai_error.log").write_text(traceback.format_exc(), encoding="utf-8")
        except OSError:
            pass
        if type(exc).__name__ == "AuthenticationError":
            detail = str(exc).strip()
            return {"answer": f"De API-authenticatie is mislukt: {detail} Maak een nieuwe API-key aan en start de app opnieuw.", "chat_title": "", "context": None, "document": None, "action": None, "roles": None, "validation": None, "graphs": None}
        return {"answer": f"De AI-aanvraag is mislukt ({type(exc).__name__}). Controleer je API-key, saldo en internetverbinding.", "chat_title": "", "context": None, "document": None, "action": None, "roles": None, "validation": None, "graphs": None}


def update_chat_context(
    prompt: str,
    answer: str,
    history: list[dict],
    previous_context: dict | None = None,
) -> dict:
    """Ask the model for a compact, reusable context record for this chat."""
    context = previous_context or {}
    api_key = secret_value("OPENAI_API_KEY")
    if not api_key:
        return context
    try:
        from openai import OpenAI

        schema = {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "active_task": {"type": "string"},
                "output_type": {"type": "string", "enum": ["none", "pdf", "docx", "xlsx", "pptx"]},
                "source_files": {"type": "array", "items": {"type": "string"}},
                "pending_actions": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary", "active_task", "output_type", "source_files", "pending_actions"],
            "additionalProperties": False,
        }
        recent = "\n".join(
            f"{item.get('role', 'user').upper()}: {item.get('content', '')}" for item in history[-8:]
        )
        request_text = (
            "Werk de blijvende context van deze docentchat bij. "
            "Bewaar alleen informatie die nodig is om vervolgopdrachten te begrijpen. "
            "Verzin niets. Bewaar geen leerlingpersoonsgegevens. "
            "Bepaal het actieve onderwerp, de huidige taak, het gevraagde bestandstype, gebruikte bestanden "
            "en onafgemaakte acties. Als er geen actief bestandstype is, gebruik output_type none. "
            "Geef uitsluitend geldig JSON terug.\n\n"
            f"VORIGE CONTEXT:\n{json.dumps(context, ensure_ascii=False)}\n\n"
            f"RECENTE CHAT:\n{recent}\n\n"
            f"NIEUWSTE AI-ANTWOORD:\n{answer}\n\n"
            f"NIEUWSTE VRAAG:\n{prompt}"
        )
        client = OpenAI(api_key=api_key)
        try:
            response = client.responses.create(
                model=os.environ.get("OPENAI_MODEL", "gpt-6-luna"),
                input=request_text,
                text={"format": {"type": "json_schema", "name": "chat_context", "strict": True, "schema": schema}},
            )
        except Exception:
            response = client.responses.create(
                model=os.environ.get("OPENAI_MODEL", "gpt-6-luna"),
                input=request_text,
                text={"format": {"type": "json_object"}},
            )
        parsed = json.loads(response.output_text)
        return parsed if isinstance(parsed, dict) else context
    except Exception:
        try:
            (DATA_ROOT / "context_error.log").write_text(traceback.format_exc(), encoding="utf-8")
        except OSError:
            pass
        return context


def edit_powerpoint(prompt: str, pptx_path: Path, state: dict, graph_specs: list[dict] | None = None) -> dict | None:
    """Use the model to create a conservative text-replacement plan for a PPTX."""
    api_key = secret_value("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI

        slide_text = extract_file_text(pptx_path)
        if slide_text.startswith("[DIT BESTAND"):
            (DATA_ROOT / "pptx_error.log").write_text(slide_text, encoding="utf-8")
            return None
        schema = {
            "type": "object",
            "properties": {
                "operations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "action": {"type": "string", "enum": ["replace_text", "add_slide"]},
                            "slide": {"type": "integer", "minimum": 1},
                            "find": {"type": "string"},
                            "replace": {"type": "string"},
                            "after_slide": {"type": "integer", "minimum": 0},
                            "title": {"type": "string"},
                            "body": {"type": "string"},
                        },
                        "required": ["action", "slide", "find", "replace", "after_slide", "title", "body"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["operations"],
            "additionalProperties": False,
        }
        client = OpenAI(api_key=api_key)
        edit_request = (
            "Maak een conservatief bewerkingsplan voor deze PowerPoint. "
            "Voer concrete tekstwijzigingen uit met action replace_text en gebruik dan de exacte bestaande tekst in find. "
            "Gebruik action add_slide wanneer de gebruiker om een nieuwe dia vraagt. "
            "Zet bij add_slide de gewenste positie in after_slide, plus een duidelijke title en body. "
            "Kopieer de gebruikersopdracht nooit letterlijk naar title of body. "
            "Houd title kort en body beperkt tot maximaal vijf korte regels met alleen de inhoud die op de dia hoort. "
            "Als de gebruiker alleen om een grafiek vraagt, laat operations leeg; de app maakt daarvoor zelf een aparte grafiekdia. "
            "Gebruik lege strings voor velden die bij de gekozen actie niet nodig zijn. "
            f"\n\nGEBRUIKERSOPDRACHT:\n{prompt}\n\nPOWERPOINT:\n{slide_text[:100000]}"
        )
        try:
            response = client.responses.create(
                model=os.environ.get("OPENAI_MODEL", "gpt-6-luna"),
                input=edit_request,
                text={"format": {"type": "json_schema", "name": "pptx_edit_plan", "strict": True, "schema": schema}},
            )
        except Exception:
            # JSON mode is a compatible fallback for models/API versions that
            # do not accept the structured-output schema above.
            response = client.responses.create(
                model=os.environ.get("OPENAI_MODEL", "gpt-6-luna"),
                input=edit_request + "\nGeef uitsluitend geldig JSON terug.",
                text={"format": {"type": "json_object"}},
            )
        plan = json.loads(response.output_text)
        operations = plan.get("operations", [])
        requested_graphs = [item for item in (graph_specs or []) if isinstance(item, dict) and item.get("requested")]
        if not operations and not requested_graphs:
            (DATA_ROOT / "pptx_error.log").write_text(
                "De AI gaf een leeg bewerkingsplan terug.\n\n" + response.output_text,
                encoding="utf-8",
            )
            return None

        from pptx import Presentation
        from pptx.util import Inches, Pt

        readable_path, temporary_path = powerpoint_snapshot(pptx_path)
        if not readable_path:
            return None
        presentation = Presentation(str(readable_path))
        applied = 0
        for operation in operations:
            action = operation.get("action")
            if action == "add_slide":
                layout = presentation.slide_layouts[6]
                new_slide = presentation.slides.add_slide(layout)
                title_box = new_slide.shapes.add_textbox(Inches(0.7), Inches(0.45), Inches(12), Inches(0.8))
                set_pptx_markdown_text(title_box.text_frame, operation.get("title", ""), Pt(28))
                body_box = new_slide.shapes.add_textbox(Inches(0.9), Inches(1.5), Inches(11.5), Inches(5.2))
                set_pptx_markdown_text(body_box.text_frame, operation.get("body", ""), Pt(20))
                slide_id = presentation.slides._sldIdLst[-1]
                presentation.slides._sldIdLst.remove(slide_id)
                insert_at = max(0, min(operation.get("after_slide", 0), len(presentation.slides._sldIdLst)))
                presentation.slides._sldIdLst.insert(insert_at, slide_id)
                applied += 1
                continue

            slide_number = operation.get("slide", 0)
            find_text = operation.get("find", "")
            replace_text = markdown_plain_text(operation.get("replace", ""))
            if not (1 <= slide_number <= len(presentation.slides) and find_text):
                continue
            slide = presentation.slides[slide_number - 1]
            for shape in slide.shapes:
                if not hasattr(shape, "text_frame") or not shape.has_text_frame:
                    continue
                shape_changed = False
                for paragraph in shape.text_frame.paragraphs:
                    if find_text in paragraph.text:
                        paragraph_font_size = (paragraph.runs[0].font.size if paragraph.runs else None) or Pt(20)
                        new_paragraph_text = paragraph.text.replace(find_text, replace_text)
                        paragraph.clear()
                        add_pptx_markdown_runs(paragraph, new_paragraph_text, paragraph_font_size)
                        applied += 1
                        shape_changed = True
                        continue
                    for run in paragraph.runs:
                        if find_text in run.text:
                            run.text = run.text.replace(find_text, replace_text)
                            applied += 1
                            shape_changed = True
                if not shape_changed and find_text in shape.text:
                    shape.text = shape.text.replace(find_text, replace_text)
                    applied += 1
        # Render each requested graph separately so an invalid graph does not
        # shift the slide assignment of the graphs that follow it.
        for graph_spec in requested_graphs:
            rendered = render_function_graphs([graph_spec])
            if not rendered:
                continue
            graph_path = rendered[0]
            reference_slide_number = int(graph_spec.get("slide", 1) or 1)
            if not (1 <= reference_slide_number <= len(presentation.slides)):
                graph_path.unlink(missing_ok=True)
                continue
            reference_slide = presentation.slides[reference_slide_number - 1]
            graph_slide = presentation.slides.add_slide(presentation.slide_layouts[6])
            title_box = graph_slide.shapes.add_textbox(Inches(0.6), Inches(0.35), Inches(12.1), Inches(0.65))
            title_text = str(graph_spec.get("title") or "Grafiek").strip() or "Grafiek"
            set_pptx_markdown_text(title_box.text_frame, title_text, Pt(26))
            for paragraph in title_box.text_frame.paragraphs:
                for run in paragraph.runs:
                    run.font.bold = True
            slide_width_in = presentation.slide_width / Inches(1)
            graph_width_in = min(10.2, slide_width_in - 1.0)
            graph_x_in = max(0.5, (slide_width_in - graph_width_in) / 2)
            graph_y_in = 1.15
            graph_slide.shapes.add_picture(str(graph_path), Inches(graph_x_in), Inches(graph_y_in), width=Inches(graph_width_in))
            # Put the new graph slide directly after its reference slide.
            new_slide_id = presentation.slides._sldIdLst[-1]
            presentation.slides._sldIdLst.remove(new_slide_id)
            reference_slide_id = reference_slide.slide_id
            reference_index = next(
                index for index, slide_id in enumerate(presentation.slides._sldIdLst)
                if int(slide_id.id) == int(reference_slide_id)
            )
            presentation.slides._sldIdLst.insert(reference_index + 1, new_slide_id)
            applied += 1
            graph_path.unlink(missing_ok=True)
        if not applied:
            (DATA_ROOT / "pptx_error.log").write_text(
                "Het bewerkingsplan bevatte geen toepasbare wijzigingen.\n\n" + json.dumps(plan, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return None
        output_name = f"{pptx_path.stem}_aangepast_{datetime.now().strftime('%H%M%S')}.pptx"
        output_path = DATA_ROOT / "generated"
        output_path.mkdir(parents=True, exist_ok=True)
        output_file = output_path / clean_name(output_name)
        presentation.save(str(output_file))
        generated = store_file_bytes(state, "root", output_file.name, output_file.read_bytes())
        output_file.unlink(missing_ok=True)
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
        return generated
    except Exception:
        try:
            (DATA_ROOT / "pptx_error.log").write_text(traceback.format_exc(), encoding="utf-8")
        except OSError:
            pass
        return None


def default_state() -> dict:
    first_id = str(uuid.uuid4())
    return {
        "active_chat": first_id,
        "chats": [
            {"id": first_id, "title": "Nieuwe chat", "updated": now_label(), "messages": [], "context": {}}
        ],
        "folders": [
            {"id": "root", "name": "Mijn bestanden", "parent": None},
        ],
        "files": [],
        "settings": {
            "subject": "",
            "level": "",
            "method": "",
            "teaching_style": "",
            "extra": "",
        },
    }


def load_state() -> dict:
    global SUPABASE_ERROR
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    FILES_ROOT.mkdir(parents=True, exist_ok=True)
    client = supabase_client() if globals().get("current_user_id") != "local_dev" else None
    remote_loaded = st.session_state.get("remote_state_initialized", False)
    if client and not remote_loaded:
        try:
            response = client.table("user_states").select("state").eq("user_id", current_user_id).limit(1).execute()
            rows = getattr(response, "data", None) or []
            if rows and isinstance(rows[0].get("state"), dict):
                STATE_FILE.write_text(json.dumps(rows[0]["state"], ensure_ascii=False, indent=2), encoding="utf-8")
                download_remote_files(rows[0]["state"], client)
            st.session_state["remote_state_initialized"] = True
        except Exception as exc:
            SUPABASE_ERROR = f"Supabase-opslag kon niet worden geladen ({type(exc).__name__})."
            try:
                (DATA_ROOT / "supabase_error.log").write_text(traceback.format_exc(), encoding="utf-8")
            except OSError:
                pass
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            changed = False
            # Remove the old starter folders, but keep all folders the user made.
            old_starter_ids = {"presentaties", "lesmateriaal"}
            filtered_folders = [f for f in state.get("folders", []) if f.get("id") not in old_starter_ids]
            if filtered_folders != state.get("folders", []):
                changed = True
            state["folders"] = filtered_folders
            if not any(f.get("id") == "root" for f in state["folders"]):
                state["folders"].insert(0, {"id": "root", "name": "Mijn bestanden", "parent": None})
                changed = True
            state.setdefault("settings", default_state()["settings"])
            for chat in state.get("chats", []):
                if "context" not in chat:
                    chat["context"] = {}
                    changed = True
            if changed:
                save_state(state)
            return state
        except (json.JSONDecodeError, OSError):
            pass
    state = default_state()
    save_state(state)
    return state


def save_state(state: dict) -> None:
    global SUPABASE_ERROR
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    client = supabase_client() if globals().get("current_user_id") != "local_dev" else None
    if client:
        try:
            upload_state_files(state, client)
            client.table("user_states").upsert({"user_id": current_user_id, "state": state}).execute()
        except Exception as exc:
            SUPABASE_ERROR = f"Supabase-opslag kon niet worden opgeslagen ({type(exc).__name__})."
            try:
                (DATA_ROOT / "supabase_error.log").write_text(traceback.format_exc(), encoding="utf-8")
            except OSError:
                pass


def sync_local_files(state: dict) -> bool:
    """Refresh stored paths and metadata after files were changed externally."""
    changed = False
    for file_info in state.get("files", []):
        local_path = resolve_file_path(file_info)
        if not local_path:
            continue
        stat = local_path.stat()
        if file_info.get("path") != str(local_path):
            file_info["path"] = str(local_path)
            changed = True
        if file_info.get("size") != stat.st_size:
            file_info["size"] = stat.st_size
            changed = True
        modified = stat.st_mtime
        if file_info.get("modified") != modified:
            file_info["modified"] = modified
            changed = True
    return changed


def get_chat(state: dict, chat_id: str) -> dict:
    return next(chat for chat in state["chats"] if chat["id"] == chat_id)


def folder_path(state: dict, folder_id: str) -> str:
    if folder_id == "root":
        return "Mijn bestanden"
    folder = next((f for f in state["folders"] if f["id"] == folder_id), None)
    if not folder:
        return "Mijn bestanden"
    parent = folder_path(state, folder["parent"]) if folder.get("parent") else ""
    return f"{parent} / {folder['name']}" if parent else folder["name"]


def settings_complete(settings: dict) -> bool:
    """The minimum profile needed to give useful lesson advice."""
    return bool(settings.get("subject", "").strip() and settings.get("level", "").strip())


st.set_page_config(page_title="SocrAItes", page_icon="✦", layout="wide", initial_sidebar_state="expanded")

st.markdown(
    """
    <style>
      :root { --ink:#172033; --muted:#64748b; --accent:#315cce; --soft:#eef3ff; }
      .stApp { background: #f7f9fc; color: var(--ink); }
      [data-testid="stSidebar"] { background: #ffffff; border-right: 1px solid #e8edf5; }
      [data-testid="stSidebar"] > div:first-child { padding-top: 1.4rem; }
      .brand { font-size: 1.35rem; font-weight: 750; letter-spacing:-.02em; color:var(--ink); margin-bottom:.15rem; }
      .tagline { color:var(--muted); font-size:.86rem; margin-bottom:1.2rem; }
      .eyebrow { color:var(--accent); text-transform:uppercase; letter-spacing:.12em; font-size:.72rem; font-weight:750; }
      .hero h1 { font-size: clamp(2rem, 4vw, 3.2rem); line-height:1.05; letter-spacing:-.04em; margin:.25rem 0 .7rem; }
      .hero p { color:var(--muted); font-size:1.05rem; max-width: 720px; }
      .note { background:var(--soft); border:1px solid #dce6ff; border-radius:16px; padding:1rem 1.1rem; color:#28447f; }
      .small-muted { color:var(--muted); font-size:.85rem; }
      .file-card { background:#fff; border:1px solid #e5eaf3; border-radius:14px; padding:.8rem 1rem; margin:.45rem 0; }
      div[data-testid="stChatMessage"] { border-radius:16px; }
      .stButton > button { border-radius:10px; border-color:#dbe3f0; }
      .stButton > button[kind="primary"] { background:#315cce; border-color:#315cce; }
      /* Keep the open navigation rail stable without breaking collapsed mode. */
      section[data-testid="stSidebar"][aria-expanded="true"], section[data-testid="stSidebar"][aria-expanded="true"] > div:first-child { width: 292px !important; min-width: 292px !important; max-width: 292px !important; }
      section[data-testid="stSidebar"][aria-expanded="false"] { width: 0 !important; min-width: 0 !important; max-width: 0 !important; }
      div[data-testid="stSidebarResizer"], [data-testid="stSidebarResizeHandle"] { display:none !important; width:0 !important; }
      /* Chat and folder rows are one continuous control with a menu at the right. */
      section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"] { gap:0 !important; }
      section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"] > div:first-child button { border-radius:10px 0 0 10px !important; border-right-width:0 !important; }
      section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"] > div:last-child button { border-radius:0 10px 10px 0 !important; }
      section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"] > div:first-child button { justify-content:flex-start !important; text-align:left !important; }
      section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"] > div:first-child button { overflow:hidden !important; white-space:nowrap !important; text-overflow:ellipsis !important; min-width:0 !important; }
      section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"] > div:last-child button { justify-content:center !important; padding-left:0 !important; padding-right:0 !important; }
      [data-testid="stPopover"] button svg, [data-testid="stPopover"] button::after,
      button[aria-haspopup="dialog"] svg, button[aria-haspopup="dialog"]::after,
      button[aria-expanded="true"] svg, button[aria-expanded="false"] svg,
      button[aria-expanded="true"]::after, button[aria-expanded="false"]::after { display:none !important; content:none !important; }
      [data-testid="stPopover"] button { justify-content:center !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

current_user_id = authenticate_user()
if current_user_id != "local_dev":
    user_folder = clean_name(current_user_id).replace(".", "_")
    DATA_ROOT = BASE_DATA_ROOT / "users" / user_folder
    FILES_ROOT = DATA_ROOT / "files"
    STATE_FILE = DATA_ROOT / "state.json"
state = load_state()
if sync_local_files(state):
    save_state(state)

with st.sidebar:
    st.markdown('<div class="brand">✦ SocrAItes</div><div class="tagline">Rust in je lesvoorbereiding.</div>', unsafe_allow_html=True)
    if SUPABASE_ERROR:
        st.error(f"{SUPABASE_ERROR} Controleer de Supabase-tabel, bucket en Secrets.")
    if configured_users():
        st.caption(f"Ingelogd als {current_user_id}")
        if st.button("Uitloggen", use_container_width=True):
            st.session_state.pop("authenticated_user", None)
            st.session_state.pop("remote_state_initialized", None)
            st.rerun()
    if st.button("＋ Nieuwe chat", use_container_width=True, type="primary"):
        empty_chat = next((c for c in state["chats"] if c.get("title") == "Nieuwe chat" and not c.get("messages")), None)
        if empty_chat:
            state["active_chat"] = empty_chat["id"]
        else:
            chat_id = str(uuid.uuid4())
            state["chats"].insert(0, {"id": chat_id, "title": "Nieuwe chat", "updated": now_label(), "messages": [], "context": {}})
            state["active_chat"] = chat_id
        st.session_state["page"] = "chat"
        save_state(state)
        st.rerun()

    st.markdown("**Chats**")
    for chat in sorted(state["chats"], key=lambda c: c.get("updated", ""), reverse=True):
        chat_left, chat_menu = st.columns([9, 1], gap="small")
        with chat_left:
            if st.session_state.get(f"rename_chat_{chat['id']}"):
                new_title = st.text_input("Nieuwe chatnaam en druk Enter", value=chat["title"], key=f"chat_title_{chat['id']}", label_visibility="collapsed")
                if new_title.strip() and new_title.strip() != chat["title"]:
                    chat["title"] = new_title.strip()
                    chat["updated"] = now_label()
                    save_state(state)
                    st.session_state.pop(f"rename_chat_{chat['id']}", None)
                    st.rerun()
            else:
                label = ("● " if chat["id"] == state["active_chat"] else "") + (chat["title"] or "Nieuwe chat")
                if st.button(label, key=f"chat_{chat['id']}", use_container_width=True):
                    state["active_chat"] = chat["id"]
                    st.session_state["page"] = "chat"
                    save_state(state)
                    st.rerun()
        with chat_menu:
            if st.button("⋯", key=f"open_chat_menu_{chat['id']}", use_container_width=True):
                st.session_state["open_chat_menu"] = None if st.session_state.get("open_chat_menu") == chat["id"] else chat["id"]
                st.rerun()
        if st.session_state.get("open_chat_menu") == chat["id"]:
            with st.container():
                if st.button("✎  Naam wijzigen", key=f"rename_chat_button_{chat['id']}", use_container_width=True):
                    st.session_state[f"rename_chat_{chat['id']}"] = True
                    st.session_state["open_chat_menu"] = None
                    st.rerun()
                if st.button("🗑  Chat verwijderen", key=f"delete_chat_button_{chat['id']}", use_container_width=True):
                    st.session_state[f"confirm_delete_chat_{chat['id']}"] = True
                    st.session_state["open_chat_menu"] = None
                    st.rerun()
        if st.session_state.get(f"confirm_delete_chat_{chat['id']}"):
            st.warning(f"Verwijder chat '{chat['title']}'?")
            confirm_col, cancel_col = st.columns(2)
            with confirm_col:
                if st.button("Ja, verwijderen", key=f"yes_delete_chat_{chat['id']}"):
                    state["chats"] = [c for c in state["chats"] if c["id"] != chat["id"]]
                    if not state["chats"]:
                        new_id = str(uuid.uuid4())
                        state["chats"] = [{"id": new_id, "title": "Nieuwe chat", "updated": now_label(), "messages": [], "context": {}}]
                    if state["active_chat"] == chat["id"]:
                        state["active_chat"] = state["chats"][0]["id"]
                    save_state(state)
                    st.rerun()
            with cancel_col:
                if st.button("Annuleren", key=f"cancel_delete_chat_{chat['id']}"):
                    st.session_state.pop(f"confirm_delete_chat_{chat['id']}", None)
                    st.rerun()

    st.divider()
    st.markdown("**Bestanden**")
    if st.button("▣ Bestanden", use_container_width=True):
        st.session_state["page"] = "files"
        st.rerun()
    if st.button("⚙ Instellingen", use_container_width=True):
        st.session_state["page"] = "settings"
        st.rerun()
    st.caption("Je bestanden worden per account opgeslagen in de beveiligde bibliotheek.")

page = st.session_state.get("page", "chat")
if page == "chat" and not settings_complete(state.get("settings", {})):
    page = "settings"

if page == "settings":
    settings = state.setdefault("settings", default_state()["settings"].copy())
    st.markdown('<div class="eyebrow">Instellingen</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero"><h1>Vertel SocrAItes hoe jij lesgeeft.</h1><p>Deze informatie wordt automatisch aan de AI meegegeven, zodat adviezen beter aansluiten op jouw lessen.</p></div>', unsafe_allow_html=True)
    st.markdown('<div class="note">Vul minimaal je vak en niveau in. Gebruik geen leerlingnamen of andere persoonsgegevens.</div>', unsafe_allow_html=True)
    with st.form("teacher_settings"):
        subject = st.text_input("Welk vak geef je?", value=settings.get("subject", ""), placeholder="Bijvoorbeeld economie")
        level = st.text_input("Aan welk niveau of welke leerjaren geef je les?", value=settings.get("level", ""), placeholder="Bijvoorbeeld 4 havo")
        method = st.text_input("Welke lesmethode gebruik je eventueel?", value=settings.get("method", ""), placeholder="Bijvoorbeeld LWEO of geen vaste methode")
        teaching_style = st.text_area("Hoe geef je meestal les?", value=settings.get("teaching_style", ""), placeholder="Bijvoorbeeld interactief, met PowerPoints, opdrachten en klassengesprekken.")
        extra = st.text_area("Zijn er nog andere voorkeuren voor de AI?", value=settings.get("extra", ""), placeholder="Bijvoorbeeld extra aandacht voor differentiatie of activerende werkvormen.")
        if st.form_submit_button("Instellingen opslaan", type="primary"):
            settings.update({"subject": subject, "level": level, "method": method, "teaching_style": teaching_style, "extra": extra})
            save_state(state)
            st.session_state["page"] = "chat"
            st.success("Instellingen opgeslagen. De AI gebruikt deze vanaf je volgende vraag.")
            st.rerun()
    if settings_complete(settings) and st.button("← Terug naar chat"):
        st.session_state["page"] = "chat"
        st.rerun()

elif page == "files":
    title_col, add_col = st.columns([8, 1], vertical_alignment="center")
    with title_col:
        st.markdown('<div class="eyebrow">Bestanden</div><div class="hero"><h1>Alles voor je lessen op één plek.</h1><p>Orden methodebestanden, PowerPoints en ander lesmateriaal in mappen. Je kunt bestanden later vanuit een chat gebruiken.</p></div>', unsafe_allow_html=True)
    with add_col:
        with st.popover("＋", use_container_width=True):
            st.markdown("**Toevoegen**")
            add_folder = st.text_input("Nieuwe map", placeholder="Mapnaam", key="add_folder_name")
            if st.button("Map maken", key="add_folder_button", use_container_width=True) and add_folder.strip():
                state["folders"].append({"id": str(uuid.uuid4()), "name": add_folder.strip(), "parent": st.session_state.get("current_folder", "root")})
                save_state(state)
                st.rerun()
            uploads_top = st.file_uploader("Document uploaden", accept_multiple_files=True, type=["pdf", "docx", "pptx", "txt", "md", "png", "jpg", "jpeg"], key="top_uploader")
            if st.button("Uploaden", key="top_upload_button", use_container_width=True) and uploads_top:
                target_folder = st.session_state.get("current_folder", "root")
                target = FILES_ROOT / target_folder
                target.mkdir(parents=True, exist_ok=True)
                for uploaded in uploads_top:
                    safe = clean_name(uploaded.name)
                    (target / safe).write_bytes(uploaded.getbuffer())
                    state["files"].append({"id": str(uuid.uuid4()), "name": safe, "folder": target_folder, "path": str(target / safe), "size": uploaded.size, "added": now_label()})
                save_state(state)
                st.rerun()
    st.markdown('<div class="note">Tip: upload alleen materiaal dat je voor de lesvoorbereiding nodig hebt. Gebruik geen leerlinggegevens.</div>', unsafe_allow_html=True)
    st.write("")
    if "current_folder" not in st.session_state:
        st.session_state["current_folder"] = "root"
    current_folder = st.session_state["current_folder"]
    if not any(f.get("id") == current_folder for f in state["folders"]):
        current_folder = "root"
        st.session_state["current_folder"] = "root"

    crumbs = folder_path(state, current_folder)
    st.markdown(f"**Locatie:** {crumbs}")
    if current_folder != "root" and st.button("← Terug naar Mijn bestanden"):
        parent = next(f.get("parent") for f in state["folders"] if f.get("id") == current_folder)
        st.session_state["current_folder"] = parent or "root"
        st.rerun()

    child_folders = [f for f in state["folders"] if f.get("parent") == current_folder]
    if child_folders:
        st.markdown("**Mappen**")
        for folder in child_folders:
            left, menu = st.columns([9, 1])
            with left:
                if st.session_state.get(f"rename_folder_{folder['id']}"):
                    new_name = st.text_input("Nieuwe mapnaam en druk Enter", value=folder["name"], key=f"folder_name_{folder['id']}", label_visibility="collapsed")
                    if new_name.strip() and new_name.strip() != folder["name"]:
                        folder["name"] = new_name.strip()
                        save_state(state)
                        st.session_state.pop(f"rename_folder_{folder['id']}", None)
                        st.rerun()
                elif st.button(f"📁  {folder['name']}", key=f"open_folder_{folder['id']}", use_container_width=True):
                    st.session_state["current_folder"] = folder["id"]
                    st.rerun()
            with menu:
                with st.popover("⋯", use_container_width=True):
                    if st.button("✎  Naam wijzigen", key=f"edit_folder_{folder['id']}", use_container_width=True):
                        st.session_state[f"rename_folder_{folder['id']}"] = True
                        st.rerun()
                    if st.button("🗑  Map verwijderen", key=f"delete_folder_{folder['id']}", use_container_width=True):
                        st.session_state[f"confirm_delete_folder_{folder['id']}"] = True
                        st.rerun()
            if st.session_state.get(f"confirm_delete_folder_{folder['id']}"):
                st.warning(f"Verwijder map '{folder['name']}' en alles daarin?")
                confirm_col, cancel_col = st.columns(2)
                with confirm_col:
                    if st.button("Ja, verwijderen", key=f"yes_delete_folder_{folder['id']}"):
                        to_remove = {folder["id"]}
                        changed = True
                        while changed:
                            changed = False
                            for candidate in state["folders"]:
                                if candidate.get("parent") in to_remove and candidate["id"] not in to_remove:
                                    to_remove.add(candidate["id"])
                                    changed = True
                        removed_files = [f for f in state["files"] if f.get("folder") in to_remove]
                        for removed_file in removed_files:
                            delete_remote_file(removed_file)
                        state["files"] = [f for f in state["files"] if f.get("folder") not in to_remove]
                        state["folders"] = [f for f in state["folders"] if f.get("id") not in to_remove]
                        save_state(state)
                        st.rerun()
                with cancel_col:
                    if st.button("Annuleren", key=f"cancel_delete_folder_{folder['id']}"):
                        st.session_state.pop(f"confirm_delete_folder_{folder['id']}", None)
                        st.rerun()
    else:
        st.caption("Nog geen mappen in deze locatie.")

    current_files = [f for f in state["files"] if f.get("folder") == current_folder]
    for file_info in current_files:
        left, menu = st.columns([9, 1])
        with left:
            if st.session_state.get(f"rename_file_{file_info['id']}"):
                new_name = st.text_input("Nieuwe bestandsnaam en druk Enter", value=file_info["name"], key=f"file_name_{file_info['id']}", label_visibility="collapsed")
                if new_name.strip() and new_name.strip() != file_info["name"]:
                    safe = clean_name(new_name)
                    old_remote_path = file_info.get("remote_path") or remote_file_path(file_info)
                    old_path = resolve_file_path(file_info)
                    if old_path:
                        new_path = old_path.with_name(safe)
                        if old_path != new_path:
                            old_path.rename(new_path)
                    else:
                        new_path = FILES_ROOT / file_info.get("folder", "root") / safe
                    file_info["name"] = safe
                    file_info["path"] = str(new_path)
                    file_info.pop("remote_path", None)
                    file_info.pop("remote_size", None)
                    file_info.pop("remote_modified", None)
                    delete_remote_file(file_info, old_remote_path)
                    save_state(state)
                    st.session_state.pop(f"rename_file_{file_info['id']}", None)
                    st.rerun()
            else:
                # The file row itself is clickable and opens the file in the
                # operating system's default application.
                if st.button(
                    f"{file_icon(file_info['name'])}  {file_info['name']}",
                    key=f"open_file_card_{file_info['id']}",
                    use_container_width=True,
                    help="Open dit bestand",
                ):
                    resolved_path = resolve_file_path(file_info)
                    if resolved_path and current_user_id != "local_dev":
                        try:
                            st.download_button(
                                "⇩ Downloaden",
                                data=resolved_path.read_bytes(),
                                file_name=file_info["name"],
                                mime=file_mime_type(resolved_path),
                                key=f"open_download_file_{file_info['id']}",
                                use_container_width=True,
                            )
                        except OSError:
                            st.error("Download tijdelijk niet beschikbaar; probeer opnieuw.")
                    elif resolved_path and open_external(str(resolved_path)):
                        if str(resolved_path) != file_info.get("path"):
                            file_info["path"] = str(resolved_path)
                            save_state(state)
                    elif not resolved_path:
                        st.error("Dit bestand staat niet meer in de lokale app-map. Upload het bestand opnieuw.")
                    else:
                        st.error("Dit bestand kan niet lokaal worden geopend.")
                st.caption(f"{file_info.get('size', 0):,} bytes · toegevoegd {file_info.get('added', '')}")
        with menu:
            with st.popover("⋯", use_container_width=True):
                if st.button("↗  Openen", key=f"open_file_{file_info['id']}", use_container_width=True):
                    resolved_path = resolve_file_path(file_info)
                    if resolved_path and current_user_id != "local_dev":
                        try:
                            st.download_button(
                                "⇩  Downloaden",
                                data=resolved_path.read_bytes(),
                                file_name=file_info["name"],
                                mime=file_mime_type(resolved_path),
                                key=f"menu_open_download_{file_info['id']}",
                                use_container_width=True,
                            )
                        except OSError:
                            st.error("Download tijdelijk niet beschikbaar; probeer opnieuw.")
                    elif resolved_path and open_external(str(resolved_path)):
                        # Keep the metadata correct if the app was moved or the
                        # file was found in a different local folder.
                        if str(resolved_path) != file_info.get("path"):
                            file_info["path"] = str(resolved_path)
                            save_state(state)
                    elif not resolved_path:
                        st.error("Dit bestand staat niet meer in de lokale app-map. Upload het bestand opnieuw.")
                    else:
                        st.error("Dit bestand kan niet lokaal worden geopend.")
                download_path = resolve_file_path(file_info)
                if download_path:
                    try:
                        download_bytes = download_path.read_bytes()
                    except OSError:
                        # OneDrive can briefly lock a file while syncing. Do
                        # not let that prevent the rest of the menu rendering.
                        st.caption("Download tijdelijk niet beschikbaar; probeer opnieuw na synchronisatie.")
                    else:
                        st.download_button(
                            "⇩  Downloaden",
                            data=download_bytes,
                            file_name=file_info["name"],
                            mime=file_mime_type(download_path),
                            key=f"download_file_{file_info['id']}",
                            use_container_width=True,
                        )
                if st.button("✎  Naam wijzigen", key=f"edit_file_{file_info['id']}", use_container_width=True):
                    st.session_state[f"rename_file_{file_info['id']}"] = True
                    st.rerun()
                other_folders = {folder_path(state, f["id"]): f["id"] for f in state["folders"] if f["id"] != current_folder}
                if other_folders:
                    destination = st.selectbox("Verplaatsen naar", list(other_folders), key=f"move_to_{file_info['id']}")
                    if st.button("Verplaatsen", key=f"move_file_{file_info['id']}", use_container_width=True):
                        target_folder = other_folders[destination]
                        old_remote_path = file_info.get("remote_path") or remote_file_path(file_info)
                        old_path = resolve_file_path(file_info)
                        target_dir = FILES_ROOT / target_folder
                        target_dir.mkdir(parents=True, exist_ok=True)
                        new_path = target_dir / file_info["name"]
                        if old_path and old_path != new_path:
                            old_path.rename(new_path)
                        file_info["folder"] = target_folder
                        file_info["path"] = str(new_path)
                        file_info.pop("remote_path", None)
                        file_info.pop("remote_size", None)
                        file_info.pop("remote_modified", None)
                        delete_remote_file(file_info, old_remote_path)
                        save_state(state)
                        st.rerun()
                if st.button("🗑  Bestand verwijderen", key=f"delete_file_{file_info['id']}", use_container_width=True):
                    st.session_state[f"confirm_delete_file_{file_info['id']}"] = True
                    st.rerun()
        if st.session_state.get(f"confirm_delete_file_{file_info['id']}"):
            st.warning(f"Verwijder '{file_info['name']}' definitief?")
            confirm_col, cancel_col = st.columns(2)
            with confirm_col:
                if st.button("Ja, verwijderen", key=f"yes_delete_file_{file_info['id']}"):
                    delete_remote_file(file_info)
                    path = resolve_file_path(file_info)
                    if path:
                        path.unlink()
                    state["files"] = [f for f in state["files"] if f.get("id") != file_info["id"]]
                    save_state(state)
                    st.rerun()
            with cancel_col:
                if st.button("Annuleren", key=f"cancel_delete_file_{file_info['id']}"):
                    st.session_state.pop(f"confirm_delete_file_{file_info['id']}", None)
                    st.rerun()
    if not current_files:
        st.info("Deze map is nog leeg.")

    if st.button("← Terug naar chat"):
        st.session_state["page"] = "chat"
        st.rerun()
else:
    chat = get_chat(state, state["active_chat"])
    st.markdown('<div class="eyebrow">Lesvoorbereiding</div>', unsafe_allow_html=True)
    if not chat["messages"]:
        st.markdown('<div class="hero"><h1>Waar werken we vandaag aan?</h1><p>Vertel welke les je voorbereidt. Voeg methodepagina’s, een PowerPoint of andere context toe wanneer dat helpt.</p></div>', unsafe_allow_html=True)
    else:
        st.subheader(chat["title"])
        for message in chat["messages"]:
            with st.chat_message(message["role"]):
                st.markdown(normalize_chat_math(message["content"]))
                if message.get("files"):
                    st.caption("Bijgevoegd: " + ", ".join(message["files"]))
                if message.get("process"):
                    with st.expander("Proces van de AI", expanded=False):
                        st.caption("Dit is de lokale rolplanning van de app. Pas na een geslaagde API-aanvraag kan de AI de inhoudelijk gekozen rollen uitvoeren.")
                        for index, step in enumerate(message["process"], start=1):
                            icon = {"Uitgevoerd": "✅", "Gestopt": "⛔", "Overgeslagen": "⏭️", "Niet uitgevoerd": "⚪"}.get(step.get("status"), "⏳")
                            st.markdown(f"**{index}. {icon} {step.get('role', 'Rol')} — {step.get('status', 'Gepland')}**  \n{step.get('task', '')}")
                generated_id = message.get("generated_file")
                if generated_id:
                    generated_info = next((item for item in state.get("files", []) if item.get("id") == generated_id), None)
                    generated_path = resolve_file_path(generated_info) if generated_info else None
                    if generated_info and generated_path:
                        try:
                            generated_suffix = generated_path.suffix.lower()
                            generated_label = {
                                ".pptx": "⇩ Download aangepaste PowerPoint",
                                ".pdf": "⇩ Download PDF",
                                ".docx": "⇩ Download Word-document",
                                ".xlsx": "⇩ Download Excel-bestand",
                            }.get(generated_suffix, "⇩ Download bestand")
                            st.download_button(
                                generated_label,
                                data=generated_path.read_bytes(),
                                file_name=generated_info["name"],
                                mime=file_mime_type(generated_path),
                                key=f"download_generated_{generated_id}",
                            )
                        except OSError:
                            st.caption("Download tijdelijk niet beschikbaar; probeer opnieuw.")

    with st.expander("＋ Bestanden bij deze chat", expanded=False):
        chat_files = st.file_uploader("Voeg methodepagina’s, PowerPoints of andere bestanden toe", accept_multiple_files=True, type=["pdf", "docx", "pptx", "txt", "md", "png", "jpg", "jpeg"], key=f"chat_uploader_{chat['id']}")
        st.caption("Gebruik geen namen, cijfers of andere leerlinggegevens.")
    prompt = st.chat_input("Schrijf je vraag of beschrijf de les die je wilt voorbereiden…")
    if prompt:
        attached_names = []
        attached_paths = []
        if chat_files:
            chat_dir = FILES_ROOT / "chat_uploads" / chat["id"]
            chat_dir.mkdir(parents=True, exist_ok=True)
            for uploaded in chat_files:
                safe = clean_name(uploaded.name)
                saved_path = chat_dir / safe
                saved_path.write_bytes(uploaded.getbuffer())
                attached_names.append(safe)
                attached_paths.append(saved_path)
        new_chat_pending = chat["title"] == "Nieuwe chat"
        chat["messages"].append({"role": "user", "content": prompt, "files": attached_names, "time": now_label()})
        chat["updated"] = now_label()
        library_paths = [
            resolved
            for file_info in state.get("files", [])
            if (resolved := resolve_file_path(file_info)) is not None
        ]
        chat_context = chat.setdefault("context", {})
        output_type = requested_output_type(prompt, chat["messages"], chat_context)
        # Dit is alleen de tijdelijke weergave tijdens de aanvraag. De definitieve
        # rolvolgorde wordt door de AI teruggegeven in dezelfde gestructureerde respons.
        process_trace = [{"role": "AI-coördinator", "task": "De vraag, chatcontext en bestanden analyseren en de benodigde rollen kiezen.", "status": "Bezig"}]
        action_kind = None
        action_output_type = None
        action_user_requested = False
        action_target_files: list[str] = []
        with st.status("AI-proces gestart", expanded=True) as process_status:
            for index, step in enumerate(process_trace, start=1):
                process_status.write(f"{index}. **{step['role']}** — {step['task']}")
            with st.spinner("De AI leest je vraag en bestanden..."):
                agent_result = ask_agent(
                    prompt,
                    chat["messages"],
                    attached_paths,
                    state.get("settings", {}),
                    library_paths,
                    chat_context,
                )
                answer = agent_result.get("answer", "") if isinstance(agent_result, dict) else str(agent_result)
                chat_title_payload = agent_result.get("chat_title", "") if isinstance(agent_result, dict) else ""
                returned_context = agent_result.get("context") if isinstance(agent_result, dict) else None
                document_payload = agent_result.get("document") if isinstance(agent_result, dict) else None
                action_payload = agent_result.get("action") if isinstance(agent_result, dict) else None
                validation_payload = agent_result.get("validation") if isinstance(agent_result, dict) else None
                graph_payload = agent_result.get("graphs") if isinstance(agent_result, dict) else None
                if new_chat_pending and isinstance(chat_title_payload, str) and chat_title_payload.strip():
                    chat["title"] = chat_title_payload.strip()[:60]
                model_roles = agent_result.get("roles") if isinstance(agent_result, dict) else None
                if isinstance(model_roles, list) and model_roles:
                    process_trace = [
                        {"role": item.get("role"), "task": item.get("task"), "status": "Gepland"}
                        for item in model_roles
                        if isinstance(item, dict) and item.get("role") and item.get("task")
                    ]
                if isinstance(returned_context, dict):
                    chat["context"] = returned_context
                if isinstance(action_payload, dict):
                    action_kind = action_payload.get("kind")
                    action_output_type = action_payload.get("output_type")
                    action_user_requested = bool(action_payload.get("user_requested"))
                    action_target_files = [str(name).strip() for name in action_payload.get("target_files", []) if str(name).strip()]
                    if action_kind == "create_document" and action_output_type in {"pdf", "docx", "xlsx"}:
                        output_type = action_output_type
                    elif action_kind == "answer_only":
                        output_type = None
                if not process_trace or process_trace[0]["role"] == "AI-coördinator":
                    process_trace = [{"role": "AI-coördinator", "task": "De AI kon geen rolplan teruggeven.", "status": "Niet uitgevoerd"}]
            process_status.update(label="AI-proces afgerond", state="complete", expanded=False)
        generated_file = None
        validation_status = validation_payload.get("status") if isinstance(validation_payload, dict) else None
        validation_blocked = action_kind == "create_document" and validation_status in {"blocked", "needs_information"}
        if validation_blocked and isinstance(validation_payload, dict):
            reasons = [str(reason).strip() for reason in validation_payload.get("reasons", []) if str(reason).strip()]
            if reasons and not any(reason.lower() in answer.lower() for reason in reasons):
                answer += "\n\nIk maak het bestand nog niet, omdat de inhoud eerst gecontroleerd moet worden:\n" + "\n".join(f"- {reason}" for reason in reasons)
            output_type = None
        hard_stop = ai_requested_hard_stop(answer) or validation_blocked
        request_failed = ai_request_failed(answer)
        if hard_stop:
            for step in process_trace:
                step["status"] = "Gestopt" if step["role"] == "Bestandenlezer" else "Overgeslagen"
        elif request_failed:
            for step in process_trace:
                step["status"] = "Niet uitgevoerd"
        else:
            for step in process_trace:
                step["status"] = "Uitgevoerd"
        requested_target_names = {Path(name).name.casefold() for name in action_target_files}
        pptx_candidates = [
            path for path in (attached_paths + library_paths)
            if path.suffix.lower() == ".pptx" and path.name.casefold() in requested_target_names
        ]
        has_powerpoint_role = any(step.get("role") == "PowerPoint-bewerker" for step in process_trace)
        powerpoint_action_requested = action_kind == "edit_powerpoint" and action_user_requested and has_powerpoint_role
        should_edit_powerpoint = powerpoint_action_requested and bool(pptx_candidates)
        if not hard_stop and not request_failed and powerpoint_action_requested and not pptx_candidates:
            answer += "\n\nIk zie geen PowerPoint-bestand dat ik kan bewerken. Voeg een `.pptx` toe aan de bestandsbibliotheek of aan deze chat."
        for attached_path in ([] if hard_stop or request_failed else pptx_candidates):
            if attached_path.suffix.lower() == ".pptx":
                with st.spinner("De AI maakt een aangepaste PowerPoint..."):
                    generated_file = edit_powerpoint(prompt, attached_path, state, graph_payload)
                if generated_file:
                    answer += f"\n\nIk heb een aangepaste PowerPoint gemaakt: **{generated_file['name']}**. Je kunt deze downloaden via Bestanden."
                elif should_edit_powerpoint:
                    answer += "\n\nIk kon de PowerPoint nog niet veilig aanpassen. Controleer of het bestand beschikbaar is en probeer dezelfde opdracht opnieuw."
                break
        document_generated = False
        if not hard_stop and not request_failed and output_type and not generated_file:
            document_content = answer
            if isinstance(document_payload, dict) and document_payload.get("requested") and document_payload.get("content"):
                document_content = document_payload["content"]
            with st.spinner(f"Ik maak het {output_type.upper()}-bestand..."):
                if output_type == "pdf":
                    generated_file = create_pdf_from_text((document_payload or {}).get("title") or "Leshand-out", document_content, state, graph_payload)
                elif output_type == "docx":
                    generated_file = create_docx_from_text((document_payload or {}).get("title") or "Lesdocument", document_content, state, graph_payload)
                else:
                    generated_file = create_xlsx_from_text((document_payload or {}).get("title") or "Lesmateriaal", document_content, state)
            if generated_file:
                document_generated = True
                answer = f"Ik heb het bestand **{generated_file['name']}** gemaakt. Je kunt het direct hieronder downloaden."
        if not hard_stop and not request_failed:
            if should_edit_powerpoint:
                for step in process_trace:
                    if step["role"] == "PowerPoint-bewerker":
                        step["status"] = "Uitgevoerd" if generated_file else "Gestopt"
            if output_type:
                for step in process_trace:
                    if step["role"] == "Documentmaker":
                        step["status"] = "Uitgevoerd" if document_generated else ("Overgeslagen" if generated_file else "Gestopt")
        assistant_message = {"role": "assistant", "content": answer, "time": now_label(), "process": process_trace}
        if generated_file:
            assistant_message["generated_file"] = generated_file["id"]
        chat["messages"].append(assistant_message)
        save_state(state)
        st.rerun()
