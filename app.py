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

from flask import Flask, Response, abort, jsonify, redirect, render_template, request, url_for

from ai_engine import AIDetector
from firewall_core import inspect_request
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
    if "KalkanReport" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("KalkanReport", str(font_path)))

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
        "KalkanReportNormal",
        fontName="KalkanReport",
        fontSize=8,
        leading=10,
    )
    header = ParagraphStyle(
        "KalkanReportHeader",
        parent=normal,
        textColor=colors.white,
    )
    title = ParagraphStyle(
        "KalkanReportTitle",
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
            Paragraph("Kalkan — Web Güvenlik Raporu", title),
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
    app.config.from_mapping(
        DATABASE=os.environ.get(
            "FIREWALL_DATABASE",
            str(Path(app.root_path) / "instance" / "firewall.sqlite3"),
        ),
        AI_MODEL_PATH=str(Path(app.root_path) / "models" / "random_forest.joblib"),
        AI_VECTORIZER_PATH=str(Path(app.root_path) / "models" / "vectorizer.joblib"),
        AI_CNN_MODEL_PATH=str(Path(app.root_path) / "models" / "1d_cnn.keras"),
        AI_METRICS_PATH=str(Path(app.root_path) / "models" / "metrics.json"),
    )
    if test_config:
        app.config.update(test_config)
    initialize(app.config["DATABASE"])
    ai_detector = AIDetector(
        app.config["AI_MODEL_PATH"],
        app.config["AI_VECTORIZER_PATH"],
        app.config["AI_CNN_MODEL_PATH"],
    )
    app.extensions["ai_detector"] = ai_detector

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
            "source": request.remote_addr or "Yerel",
            "method": method,
            "path": path,
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
        user_agent = "KalkanLocalSimulation/1.0"
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
                "path": logged_path,
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
            headers={"Content-Disposition": "attachment; filename=kalkan_logs.csv"},
        )

    @app.get("/export/pdf")
    def export_pdf():
        events = recent_events(app.config["DATABASE"], 50)
        return Response(
            _create_pdf(events),
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=kalkan_rapor.pdf"},
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
    app.run(host="127.0.0.1", port=5000, debug=False)
