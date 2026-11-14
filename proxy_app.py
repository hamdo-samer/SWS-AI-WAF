import urllib.parse
import requests
from flask import Flask, request, Response
from firewall_core import inspect_request
from ai_engine import AIDetector, AIPrediction
from storage import initialize, add_event

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
TARGET_SITE = "http://127.0.0.1:8080"
DB_PATH = "instance/firewall.sqlite3"
initialize(DB_PATH)
ai_detector = AIDetector()


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    raw_target = request.environ.get("RAW_URI") or request.environ.get("REQUEST_URI")
    raw_path = raw_target.split("?", 1)[0] if raw_target else "/" + path
    if not raw_path.startswith("/"):
        raw_path = "/" + path
    try:
        query_string = request.query_string.decode("utf-8")
    except UnicodeDecodeError:
        return Response("Invalid query encoding", status=400, mimetype="text/plain")

    method = request.method
    user_agent = request.headers.get('User-Agent', '')
    body_bytes = request.get_data(cache=True)
    body = body_bytes.decode("utf-8", errors="replace")
    body_content_type = request.headers.get("Content-Type", "")

    # Inspect the same raw path and query representation that will be forwarded.
    try:
        result = inspect_request(
            raw_path,
            method,
            query_string,
            user_agent,
            body,
            body_content_type,
        )
    except ValueError as error:
        return Response(str(error), status=413, mimetype="text/plain")
    except TypeError as error:
        return Response(str(error), status=400, mimetype="text/plain")

    # Ignore AI analysis for static assets.
    static_extensions = (
        ".css",
        ".js",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".ico",
        ".svg",
        ".woff",
        ".woff2",
    )
    static_path = urllib.parse.urlsplit(raw_path).path
    if static_path.lower().endswith(static_extensions):
        ai_result = AIPrediction(None, None, None, None)
    else:
        try:
            ai_result = ai_detector.predict(method, raw_path, query_string)
        except (RuntimeError, ValueError, TypeError, OSError):
            app.logger.exception(
                "AI advisory inference failed; continuing with the rule-engine decision."
            )
            ai_result = AIPrediction(None, None, None, None)

    final_decision = result.decision
    override_reason = ""
    if result.decision == "İzin verildi":
        confident_attack_scores = [
            confidence
            for decision, confidence in (
                (ai_result.rf_decision, ai_result.rf_confidence),
                (ai_result.dl_decision, ai_result.dl_confidence),
            )
            if decision == "Engellendi" and confidence is not None
        ]
        if max(confident_attack_scores, default=0.0) >= 0.95:
            final_decision = "Engellendi"
            override_reason = " [AI Override: Yüksek güvenli tehdit tespiti]"

    # 4. تسجيل الطلب في قاعدة البيانات
    add_event(DB_PATH, {
        "source": request.remote_addr or "Proxy",
        "method": method,
        "path": raw_path + (f"?{query_string}" if query_string else ""),
        "score": result.score,
        "decision": final_decision,
        "reasons": (
            tuple(result.reasons) + (override_reason,)
            if override_reason
            else result.reasons
        ),
        "ai_rf_result": ai_result.rf_decision,
        "ai_rf_confidence": ai_result.rf_confidence,
        "ai_dl_result": ai_result.dl_decision,
        "ai_dl_confidence": ai_result.dl_confidence,
        "attack_type": "AI-Ensemble" if override_reason else "Rule-Based",
    })

    # 5. القرار الأمني (رسالة نصية بسيطة لمنع الانهيار)
    if final_decision == "Engellendi":
        return Response(
            "Smart Web Shield (sws): Tehlikeli istek engellendi! "
            f"(403 Forbidden){override_reason}",
            status=403,
            mimetype="text/plain",
        )

    # 6. تمرير الطلب الآمن للموقع الحقيقي
    url = f"{TARGET_SITE}{raw_path}"
    if query_string:
        url += f"?{query_string}"

    try:
        resp = requests.request(
            method=method,
            url=url,
            headers={key: value for (key, value)
                     in request.headers if key != 'Host'},
            data=body_bytes,
            cookies=request.cookies,
            allow_redirects=False,
            timeout=5
        )
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))
    except Exception as e:
        return f"Siteye ulaşılamıyor: {str(e)}", 502


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
