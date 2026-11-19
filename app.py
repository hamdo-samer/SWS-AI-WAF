"""Turkish-language educational web firewall prototype."""

from __future__ import annotations

import csv
import json
import os
import sqlite3
from collections.abc import Sequence
from io import BytesIO, StringIO
from pathlib import Path
from xml.sax.saxutils import escape

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from ai_engine import AIDetector
from config import Settings
from firewall_core import inspect_request, sanitize_for_log
from storage import add_event, initialize, recent_events, statistics


_SIMULATION_SCENARIOS = {
    "sqli": "SQLi",
    "xss": "XSS",
    "cmdi": "CMDi",
}
_SIMULATION_PAYLOADS = {
    "sqli": ("/login", "user=admin' OR '1'='1"),
    "xss": ("/search", "q=<script>alert('XSS')</script>"),
    "cmdi": ("/ping", "ip=127.0.0.1; cat /etc/passwd"),
}


def _csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def _create_pdf(events: Sequence[sqlite3.Row]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    windows_directory = Path(os.environ.get("WINDIR", "C:\\Windows"))
    font_candidates = (
        windows_directory / "Fonts" / "arial.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"),
    )
    font_path = next((candidate for candidate in font_candidates if candidate.is_file()), None)
    if font_path is None:
        raise RuntimeError("A Unicode TrueType font is required to generate the PDF report.")
    if "swsReport" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("swsReport", str(font_path)))

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=28,
        rightMargin=28,
        topMargin=28,
        bottomMargin=28,
    )
    normal = ParagraphStyle(
        "swsReportNormal",
        fontName="swsReport",
        fontSize=8,
        leading=10,
    )
    header = ParagraphStyle(
        "swsReportHeader",
        parent=normal,
        textColor=colors.white,
    )
    title = ParagraphStyle(
        "swsReportTitle",
        parent=normal,
        fontSize=16,
        leading=20,
    )
    headers = ("Zaman", "Kaynak", "Yol", "Risk", "Karar", "AI (RF)")
    table_data = [[Paragraph(escape(cell), header) for cell in headers]]
    for event in events:
        values = (
            event["created_at"],
            event["source"],
            event["method"] + " " + event["path"],
            str(event["score"]),
            event["decision"],
            event["ai_rf_result"] or "—",
        )
        table_data.append(
            [Paragraph(escape(str(value)), normal) for value in values]
        )

    table = Table(
        table_data,
        colWidths=(92, 82, 300, 45, 98, 120),
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#101b2c")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#dce2eb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), (colors.white, colors.HexColor("#f5f7fa"))),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    document.build(
        [
            Paragraph("Smart Web Shield (sws) — Web Güvenlik Raporu", title),
            Paragraph("Son 50 kayıt. AI sonuçları yalnızca yapılandırılmış model varsa gösterilir.", normal),
            Spacer(1, 12),
            table,
        ]
    )
    return buffer.getvalue()


def _load_model_metrics(path: str | Path) -> dict[str, dict[str, float]]:
    metrics_path = Path(path)
    if not metrics_path.is_file():
        return {}
    with metrics_path.open(encoding="utf-8") as metrics_file:
        metrics = json.load(metrics_file)
    if not isinstance(metrics, dict):
        raise ValueError("The model metrics file must contain a JSON object.")

    required_metrics = ("accuracy", "precision", "recall", "f1")
    validated: dict[str, dict[str, float]] = {}
    for model_name, scores in metrics.items():
        if not isinstance(model_name, str) or not isinstance(scores, dict):
            raise ValueError("Each model metric entry must be a named JSON object.")
        validated_scores: dict[str, float] = {}
        for metric in required_metrics:
            value = scores.get(metric)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0 <= value <= 1
            ):
                raise ValueError(
                    f"Model metric {model_name!r}.{metric} must be a number from 0 to 1."
                )
            validated_scores[metric] = float(value)
        validated[model_name] = validated_scores
    return validated


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    settings = Settings.from_env()
    app.config.from_mapping(
        SECRET_KEY=settings.secret_key,
        DATABASE=os.environ.get(
            "FIREWALL_DATABASE",
            settings.database_url,
        ),
        AI_MODEL_PATH=str(Path(app.root_path) / "models" / "random_forest.joblib"),
        AI_VECTORIZER_PATH=str(Path(app.root_path) / "models" / "vectorizer.joblib"),
        AI_CNN_MODEL_PATH=str(Path(app.root_path) / "models" / "1d_cnn.keras"),
        AI_METRICS_PATH=str(Path(app.root_path) / "models" / "metrics.json"),
        ADMIN_USERNAME=settings.admin_username,
        ADMIN_PASSWORD=settings.admin_password,
        ADMIN_PASSWORD_HASH=settings.admin_password_hash,
        CSRF_ENABLED=settings.csrf_enabled,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower()
        in {"1", "true", "yes", "on"},
        PERMANENT_SESSION_LIFETIME=1800,
        DASHBOARD_HOST=settings.dashboard_host,
        DASHBOARD_PORT=settings.dashboard_port,
        TRUSTED_PROXY_CIDRS=settings.trusted_proxy_cidrs,
    )
    if test_config:
        app.config.update(test_config)
    if app.config.get("TESTING"):
        app.config.setdefault("CSRF_ENABLED", False)
    initialize(app.config["DATABASE"])
    ai_detector = AIDetector(
        app.config["AI_MODEL_PATH"],
        app.config["AI_VECTORIZER_PATH"],
        app.config["AI_CNN_MODEL_PATH"],
    )
    app.extensions["ai_detector"] = ai_detector

    def _csrf_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = os.urandom(32).hex()
            session["csrf_token"] = token
        return token

    def _credentials_configured() -> bool:
        return bool(
            app.config.get("ADMIN_PASSWORD")
            or app.config.get("ADMIN_PASSWORD_HASH")
        )

    def _password_matches(password: str) -> bool:
        password_hash = app.config.get("ADMIN_PASSWORD_HASH")
        if password_hash:
            return check_password_hash(password_hash, password)
        configured_password = app.config.get("ADMIN_PASSWORD")
        if configured_password:
            return secrets_compare(configured_password, password)
        if app.config.get("TESTING"):
            return secrets_compare("admin", password)
        return False

    def secrets_compare(expected: str, supplied: str) -> bool:
        from hmac import compare_digest

        return compare_digest(expected, supplied)

    @app.context_processor
    def template_security_context():
        return {"csrf_token": _csrf_token()}

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; frame-ancestors 'none'",
        )
        response.headers.setdefault(
            "Cache-Control",
            "no-store, max-age=0",
        )
        return response

    @app.before_request
    def protect_admin_routes():
        if app.config.get("TESTING"):
            return None
        protected_prefixes = (
            "/panel",
            "/gunluk",
            "/api/ozet",
            "/export/",
        )
        if request.method == "POST" and app.config.get("CSRF_ENABLED"):
            if request.endpoint != "login":
                submitted = request.form.get("csrf_token") or request.headers.get(
                    "X-CSRF-Token", ""
                )
                if not submitted or not secrets_compare(
                    session.get("csrf_token", ""),
                    submitted,
                ):
                    abort(403, description="Geçersiz veya eksik CSRF belirteci.")

        if any(request.path == prefix or request.path.startswith(prefix)
               for prefix in protected_prefixes):
            if not session.get("admin_authenticated"):
                return redirect(url_for("login", next=request.full_path.rstrip("?")))

    @app.get("/giris")
    def login():
        if session.get("admin_authenticated"):
            return redirect(url_for("dashboard"))
        if not _credentials_configured() and not app.config.get("TESTING"):
            return (
                render_template(
                    "login.html",
                    login_error="ADMIN_PASSWORD veya ADMIN_PASSWORD_HASH ortam değişkeni ayarlanmalıdır.",
                ),
                503,
            )
        return render_template("login.html")

    @app.post("/giris")
    def login_submit():
        if not _credentials_configured() and not app.config.get("TESTING"):
            abort(503, description="Yönetici kimlik bilgileri yapılandırılmamış.")
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if (
            secrets_compare(app.config["ADMIN_USERNAME"], username)
            and _password_matches(password)
        ):
            session.clear()
            session["admin_authenticated"] = True
            session.permanent = True
            next_url = request.args.get("next", "")
            if next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))
        return render_template(
            "login.html",
            login_error="Kullanıcı adı veya parola hatalı.",
        ), 401

    @app.post("/cikis")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            result=None,
            ai_available=ai_detector.is_available,
            ai_rf_available=ai_detector.rf_available,
            ai_dl_available=ai_detector.dl_available,
        )

    @app.post("/incele")
    def inspect():
        path = request.form.get("path", "").strip()
        method = request.form.get("method", "GET").strip().upper()
        query = request.form.get("query", "").strip()
        user_agent = request.form.get("user_agent", "").strip()

        if not path or len(path) > 4096:
            abort(400, description="İstek yolu boş olamaz ve 4096 karakteri aşamaz.")

        try:
            result = inspect_request(path, method, query, user_agent)
        except (TypeError, ValueError) as error:
            abort(400, description=str(error))

        ai_prediction = (
            ai_detector.predict(method, path, query)
            if ai_detector.is_available
            else None
        )
        event = {
            "source": sanitize_for_log(request.remote_addr or "Yerel"),
            "method": method,
            "path": sanitize_for_log(path),
            "score": result.score,
            "decision": result.decision,
            "reasons": result.reasons,
            "ai_rf_result": ai_prediction.rf_decision if ai_prediction else None,
            "ai_rf_confidence": ai_prediction.rf_confidence if ai_prediction else None,
            "ai_dl_result": ai_prediction.dl_decision if ai_prediction else None,
            "ai_dl_confidence": ai_prediction.dl_confidence if ai_prediction else None,
            "attack_type": None,
        }
        add_event(app.config["DATABASE"], event)
        return render_template(
            "index.html",
            result=event,
            ai_available=ai_detector.is_available,
            ai_rf_available=ai_detector.rf_available,
            ai_dl_available=ai_detector.dl_available,
        )

    @app.get("/simulasyon")
    def simulation_page():
        return render_template(
            "simulation.html",
            scenarios=_SIMULATION_SCENARIOS,
            ai_available=ai_detector.is_available,
        )

    @app.post("/simulasyon/gonder")
    def send_simulated_scenario():
        scenario = request.form.get("attack_type", "")
        if scenario not in _SIMULATION_SCENARIOS:
            abort(400, description="Geçersiz yerel senaryo seçimi.")

        attack_type = _SIMULATION_SCENARIOS[scenario]
        path, query = _SIMULATION_PAYLOADS[scenario]
        user_agent = "swsLocalSimulation/1.0"
        result = inspect_request(path, "GET", query, user_agent)
        ai_prediction = (
            ai_detector.predict("GET", path, query)
            if ai_detector.is_available
            else None
        )
        logged_path = path + ("&" if "?" in path else "?") + query
        add_event(
            app.config["DATABASE"],
            {
                "source": "Yerel simülasyon",
                "method": "GET",
                "path": sanitize_for_log(logged_path),
                "score": result.score,
                "decision": result.decision,
                "reasons": (
                    *result.reasons,
                    "Yük yalnızca yerel olarak incelendi; ağ isteği veya komut çalıştırılmadı.",
                ),
                "ai_rf_result": ai_prediction.rf_decision if ai_prediction else None,
                "ai_rf_confidence": ai_prediction.rf_confidence if ai_prediction else None,
                "ai_dl_result": ai_prediction.dl_decision if ai_prediction else None,
                "ai_dl_confidence": ai_prediction.dl_confidence if ai_prediction else None,
                "attack_type": attack_type,
            },
        )
        return redirect(url_for("logs"))

    @app.get("/panel")
    def dashboard():
        return render_template(
            "dashboard.html",
            stats=statistics(app.config["DATABASE"]),
            events=recent_events(app.config["DATABASE"], 8),
            model_metrics=_load_model_metrics(app.config["AI_METRICS_PATH"]),
        )

    @app.get("/gunluk")
    def logs():
        return render_template(
            "logs.html", events=recent_events(app.config["DATABASE"], 200)
        )

    @app.get("/hakkinda")
    def about():
        return render_template("about.html")

    @app.get("/api/ozet")
    def summary():
        return jsonify(statistics(app.config["DATABASE"]))

    @app.get("/export/csv")
    def export_csv():
        events = recent_events(app.config["DATABASE"], 1000)
        output = StringIO(newline="")
        csv_writer = csv.writer(output)
        csv_writer.writerow(
            [
                "Zaman",
                "Kaynak",
                "Yöntem",
                "Yol",
                "Risk",
                "Karar",
                "AI (RF)",
                "AI güveni (RF)",
                "AI (DL)",
                "AI güveni (DL)",
                "Saldırı türü",
            ]
        )
        for event in events:
            csv_writer.writerow(
                [
                    _csv_safe(event["created_at"]),
                    _csv_safe(event["source"]),
                    _csv_safe(event["method"]),
                    _csv_safe(event["path"]),
                    event["score"],
                    _csv_safe(event["decision"]),
                    _csv_safe(event["ai_rf_result"]),
                    event["ai_rf_confidence"],
                    _csv_safe(event["ai_dl_result"]),
                    event["ai_dl_confidence"],
                    _csv_safe(event["attack_type"]),
                ]
            )
        return Response(
            "\ufeff" + output.getvalue(),
            content_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=sws_logs.csv"},
        )

    @app.get("/export/pdf")
    def export_pdf():
        events = recent_events(app.config["DATABASE"], 50)
        return Response(
            _create_pdf(events),
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=sws_rapor.pdf"},
        )

    @app.get("/saglik")
    def health():
        return jsonify({"durum": "çalışıyor"})

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=error.description), 400

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=app.config["DASHBOARD_HOST"],
        port=app.config["DASHBOARD_PORT"],
        debug=False,
    )
