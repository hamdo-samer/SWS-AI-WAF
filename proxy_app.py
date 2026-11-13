import requests
from flask import Flask, request, render_template, Response
# ملاحظة: تم حذف abort لأنه غير مستخدم
from firewall_core import inspect_request
from ai_engine import AIDetector
from storage import initialize, add_event

app = Flask(__name__)
TARGET_SITE = "http://127.0.0.1:8080"  # مكان تشغيل نسخة موقعك المحلية
DB_PATH = "instance/firewall.sqlite3"
initialize(DB_PATH)
ai_detector = AIDetector()


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    # 1. استقبال الطلب وبناء المسار الكامل
    full_path = "/" + path
    query_string = request.query_string.decode('utf-8')
    if query_string:
        full_path += "?" + query_string

    method = request.method
    user_agent = request.headers.get('User-Agent', '')

    # 2. تمرير الطلب لمحرك القواعد والذكاء الاصطناعي
    result = inspect_request(full_path, method, "", user_agent)
    ai_result = ai_detector.predict(method, full_path, "")

    # 3. تسجيل الطلب (باستخدام الخصائص . بدلاً من [ ] لأنها Dataclass)
    # تم استخدام (أو 0) لتجنب خطأ إذا كانت قيمة الثقة None
    add_event(DB_PATH, {
        "source": request.remote_addr or "Proxy",
        "method": method,
        "path": full_path,
        "score": result.score,
        "decision": result.decision,
        "reasons": result.reasons,
        "ai_rf": f"{ai_result.rf_decision} ({int((ai_result.rf_confidence or 0)*100)}%)",
        "ai_dl": f"{ai_result.dl_decision} ({int((ai_result.dl_confidence or 0)*100)}%)",
        "scenario": "Canli Proxy"
    })

    # 4. القرار الأمني (إذا كان هجوماً نرفضه)
    if result.decision == "Engellendi":
        return render_template("error.html", code=403, message="Kalkan WAF: Tehlikeli istek engellendi!"), 403

    # 5. تمرير الطلب الآمن للموقع الحقيقي (مع الحفاظ على معاملات الاستعلام)
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
            allow_redirects=False
        )
        # إصلاح نوع الإرجاع ليتوافق مع Flask (استخدام dict للهيدرز و Response للكائن)
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))
    except Exception as e:
        return f"Siteye ulaşılamıyor: {str(e)}", 502


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
