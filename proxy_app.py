import urllib.parse
import requests
from flask import Flask, request, Response
from firewall_core import inspect_request
from ai_engine import AIDetector, AIPrediction
from storage import initialize, add_event
from config import Settings
import ipaddress
from firewall_core import sanitize_for_log


settings = Settings.from_env()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
TARGET_SITE = settings.backend_url
DB_PATH = settings.database_url
initialize(DB_PATH)
ai_detector = AIDetector()


def trusted_proxy_networks() -> tuple[ipaddress._BaseNetwork, ...]:
    networks = []
    for cidr in settings.trusted_proxy_cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def client_ip() -> str:
    remote = request.remote_addr or "Proxy"
    try:
        remote_address = ipaddress.ip_address(remote)
    except ValueError:
        return "Proxy"
    if not any(remote_address in network for network in trusted_proxy_networks()):
        return remote
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        candidates = [item.strip() for item in forwarded.split(",")]
        for candidate in candidates:
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                continue
    return remote


@app.after_request
def security_headers(response: Response) -> Response:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    )
    return response


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

    # 4. تسجيل الطلب في قاعدة البيانات
    add_event(DB_PATH, {
        "source": sanitize_for_log(client_ip()),
        "method": method,
        "path": sanitize_for_log(
            raw_path + (f"?{query_string}" if query_string else "")
        ),
        "score": result.score,
        "decision": result.decision,
        "reasons": result.reasons,
        "ai_rf_result": ai_result.rf_decision,
        "ai_rf_confidence": ai_result.rf_confidence,
        "ai_dl_result": ai_result.dl_decision,
        "ai_dl_confidence": ai_result.dl_confidence,
        "attack_type": "Canli Proxy"
    })

    # 5. القرار الأمني (رسالة نصية بسيطة لمنع الانهيار)
    if result.decision == "Engellendi":
        return Response("Smart Web Shield (sws): Tehlikeli istek engellendi! (403 Forbidden)", status=403, mimetype="text/plain")

    # 6. تمرير الطلب الآمن للموقع الحقيقي
    url = f"{TARGET_SITE}{raw_path}"
    if query_string:
        url += f"?{query_string}"

    try:
        forwarding_headers = {}
        for key, value in request.headers:
            if key.lower() in {
                "host",
                "content-length",
                "connection",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
                "forwarded",
                "x-forwarded-for",
                "x-forwarded-host",
                "x-forwarded-proto",
            }:
                continue
            forwarding_headers[key] = value
        forwarding_headers["X-Forwarded-For"] = client_ip()
        forwarding_headers["X-Forwarded-Proto"] = request.scheme
        forwarding_headers["X-Forwarded-Host"] = request.host
        resp = requests.request(
            method=method,
            url=url,
            headers=forwarding_headers,
            data=body_bytes,
            cookies=request.cookies,
            allow_redirects=False,
            timeout=5
        )
        response_headers = {
            key: value
            for key, value in resp.headers.items()
            if key.lower() not in {
                "connection",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
                "content-length",
                "content-encoding",
            }
        }
        return Response(resp.content, status=resp.status_code, headers=response_headers)
    except requests.Timeout:
        return "Siteye ulaşılamıyor: upstream zaman aşımına uğradı", 502
    except requests.ConnectionError:
        return "Siteye ulaşılamıyor: upstream bağlantı hatası", 502
    except requests.RequestException as error:
        app.logger.warning("Upstream request failed: %s", type(error).__name__)
        return "Siteye ulaşılamıyor", 502


if __name__ == "__main__":
    app.run(host=settings.proxy_host, port=settings.proxy_port, debug=False)
