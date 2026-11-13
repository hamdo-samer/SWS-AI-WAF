import urllib.parse
import requests
from flask import Flask, request, Response
from firewall_core import inspect_request
from ai_engine import AIDetector
from storage import initialize, add_event

app = Flask(__name__)
TARGET_SITE = "http://127.0.0.1:8080"
DB_PATH = "instance/firewall.sqlite3"
initialize(DB_PATH)
ai_detector = AIDetector()


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    # 1. استقبال الطلب
    full_path = "/" + path
    query_string = request.query_string.decode('utf-8')
    if query_string:
        full_path += "?" + query_string

    method = request.method
    user_agent = request.headers.get('User-Agent', '')

    # 2. فك تشفير المسار (لمنع تخطي الفحص بالهجمات المشفرة)
    decoded_path = urllib.parse.unquote(full_path)

    # 3. تمرير الطلب المفكوك لمحرك القواعد والذكاء الاصطناعي
    result = inspect_request(decoded_path, method, "", user_agent)
    ai_result = ai_detector.predict(method, decoded_path, "")

    # 4. تسجيل الطلب في قاعدة البيانات
    add_event(DB_PATH, {
        "source": request.remote_addr or "Proxy",
        "method": method,
        "path": decoded_path,
        "score": result.score,
        "decision": result.decision,
        "reasons": result.reasons,
        "ai_rf_result": str(ai_result.rf_decision),
        "ai_rf_confidence": float(ai_result.rf_confidence or 0.0),
        "ai_dl_result": str(ai_result.dl_decision),
        "ai_dl_confidence": float(ai_result.dl_confidence or 0.0),
        "attack_type": "Canli Proxy"
    })

    # 5. القرار الأمني (رسالة نصية بسيطة لمنع الانهيار)
    if result.decision == "Engellendi":
        return Response("Smart Web Shield (sws): Tehlikeli istek engellendi! (403 Forbidden)", status=403, mimetype="text/plain")

    # 6. تمرير الطلب الآمن للموقع الحقيقي
    url = f"{TARGET_SITE}/{path}"
    if query_string:
        url += f"?{query_string}"

    try:
        resp = requests.request(
            method=method,
            url=url,
            headers={key: value for (key, value)
                     in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=5
        )
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))
    except Exception as e:
        return f"Siteye ulaşılamıyor: {str(e)}", 502


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
