from flask import Flask, render_template, request, send_from_directory, abort, jsonify
from pathlib import Path
import os
import requests
import logging

app = Flask(__name__)

UPLOAD_DIR = Path("static/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# --- Firebase (hiện chưa dùng, giữ lại nếu sau này cần) ---
FIREBASE_DB_URL = os.getenv(
    "FIREBASE_DB_URL",
    "https://visiflowapk-a036d-default-rtdb.asia-southeast1.firebasedatabase.app/"
).strip()
FIREBASE_AUTH = os.getenv("FIREBASE_DB_AUTH", "").strip()
FIREBASE_LOC_PATH = os.getenv("FIREBASE_points_PATH", "points").strip()
FIREBASE_B64_PATH = os.getenv("FIREBASE_BASE64_PATH", "base64").strip()

# --- ThingsBoard (REST) ---
TB_BASE_URL = os.getenv("TB_BASE_URL", "https://visiflow-dev.m-tech.com.vn/").strip()
TB_USERNAME = os.getenv("TB_USERNAME", "visiflow@d-soft.com.vn").strip()
TB_PASSWORD = os.getenv("TB_PASSWORD", "Dsoft@1234").strip()

TB_ORIGINS = os.getenv(
    "TB_FRAME_ANCESTORS",
    "https://visiflow-dev.m-tech.com.vn https://thingsboard.cloud"
).strip()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def _fb_base():
    return FIREBASE_DB_URL if FIREBASE_DB_URL.endswith("/") else FIREBASE_DB_URL + "/"


def _tb_shared_attr_url(device_id: str) -> str:
    """
    URL để WRITE shared attributes (SHARED_SCOPE).
    """
    base = TB_BASE_URL.rstrip("/")
    return f"{base}/api/plugins/telemetry/DEVICE/{device_id}/SHARED_SCOPE"


def _tb_shared_attr_values_url(device_id: str, keys: str | None = None) -> str:
    """
    URL để READ shared attributes (SHARED_SCOPE).
    Ví dụ:
      GET /api/plugins/telemetry/DEVICE/{deviceId}/values/attributes/SHARED_SCOPE?keys=points
    """
    base = TB_BASE_URL.rstrip("/")
    url = f"{base}/api/plugins/telemetry/DEVICE/{device_id}/values/attributes/SHARED_SCOPE"
    if keys:
        url += f"?keys={keys}"
    return url


def _tb_login() -> str:
    """Login ThingsBoard và trả JWT token."""
    if not TB_USERNAME or not TB_PASSWORD:
        raise RuntimeError("Missing TB_USERNAME or TB_PASSWORD")

    base = TB_BASE_URL.rstrip("/")
    url = f"{base}/api/auth/login"
    resp = requests.post(
        url,
        json={"username": TB_USERNAME, "password": TB_PASSWORD},
        timeout=10,
    )
    resp.raise_for_status()
    body = resp.json()
    token = body.get("token")
    if not token:
        raise RuntimeError(f"Login to ThingsBoard succeeded but no 'token' in response: {body}")
    return token


@app.get("/")
def index():
    """
    Trang viewer WebRTC + annotation.
    Device sẽ được nhận DYNAMIC từ widget TB qua window.postMessage,
    không phụ thuộc query string.
    """
    image = request.args.get("image")
    if not image:
        files = sorted(
            UPLOAD_DIR.glob("image_*.*"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if files:
            image = files[0].name

    device_id = (request.args.get("deviceId") or "").strip()
    device_name = (request.args.get("deviceName") or "").strip()

    if device_id:
        app.logger.info("Index (debug) với deviceId=%s, deviceName=%s", device_id, device_name)

    return render_template(
        "index.html",
        image=image,
        title="Viewport Viewer",
        FB_BASE=_fb_base(),
        FB_AUTH_QS=(f"?auth={FIREBASE_AUTH}" if FIREBASE_AUTH else ""),
        FB_LOC_PATH=FIREBASE_LOC_PATH,
        FB_B64_PATH=FIREBASE_B64_PATH,
        DEVICE_ID=device_id,
        DEVICE_NAME=device_name,
    )


@app.get("/static/uploads/<path:fname>")
def serve_upload(fname):
    resp = send_from_directory(UPLOAD_DIR, fname)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.get("/devices")
def list_devices():
    """Endpoint debug: xem danh sách device từ TB."""
    url = TB_BASE_URL.rstrip("/") + "/api/devices"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
    except requests.RequestException as e:
        app.logger.error("ThingsBoard /api/devices failed: %s", e)
        abort(502, f"ThingsBoard /api/devices failed: {e}")

    try:
        data = r.json()
    except ValueError:
        abort(502, "Invalid JSON from ThingsBoard /api/devices")

    return jsonify(data)


def _parse_points_string(value: str):
    """
    Parse chuỗi "{x1,y1;x2,y2;...}" thành list [{x, y}, ...].
    Nếu value là "{}", "", None -> trả về [].
    Bỏ qua entry lỗi.
    """
    points = []
    if not value:
        return points

    s = str(value).strip()
    if s == "{}":
        return points

    if s.startswith("{") and s.endswith("}"):
        s = s[1:-1].strip()

    if not s:
        return points

    for chunk in s.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            x_str, y_str = chunk.split(",", 1)
            x = int(float(x_str))
            y = int(float(y_str))
            points.append({"x": x, "y": y})
        except Exception:
            continue

    return points


@app.get("/load_points")
def load_points():
    """
    Đọc shared attribute 'points' từ TB cho 1 device.
    Query:
      /load_points?deviceId=<UUID>&deviceName=<optional>

    Trả về:
      {
        "ok": true,
        "deviceId": "...",
        "deviceName": "...",
        "raw": "{400,89;853,61;...}",
        "points": [ {"x":400,"y":89}, ... ],
        "count": N
      }
    """
    device_id = (request.args.get("deviceId") or "").strip()
    device_name = (request.args.get("deviceName") or "").strip()

    if not device_id:
        abort(400, "Missing 'deviceId'")

    app.logger.info("Load points cho device %s (%s)", device_id, device_name)

    try:
        jwt_token = _tb_login()
    except Exception as e:
        app.logger.error("ThingsBoard login failed on load_points: %s", e)
        abort(502, f"ThingsBoard login failed: {e}")

    url = _tb_shared_attr_values_url(device_id, keys="points")
    headers = {
        "X-Authorization": f"Bearer {jwt_token}",
    }

    try:
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
    except requests.RequestException as e:
        app.logger.error("ThingsBoard load_points request failed: %s", e)
        abort(502, f"ThingsBoard load_points request failed: {e}")

    try:
        body = r.json()
    except ValueError:
        abort(502, "Invalid JSON from ThingsBoard load_points")

    raw_value = None

    # ThingsBoard thường trả về list các attribute
    if isinstance(body, list):
        for item in body:
            if isinstance(item, dict) and item.get("key") == "points":
                raw_value = item.get("value")
                break
    elif isinstance(body, dict):
        # fallback nếu format khác
        if "points" in body:
            raw_value = body["points"]

    parsed_points = _parse_points_string(raw_value) if raw_value is not None else []

    return jsonify(
        ok=True,
        deviceId=device_id,
        deviceName=device_name,
        raw=raw_value,
        points=parsed_points,
        count=len(parsed_points),
    )


@app.post("/save_points")
def save_points():
    """
    Body: {
      "image": "...",
      "points": [ {"x":123,"y":456}, ... ],
      "deviceId": "TB device UUID",
      "deviceName": "optional"
    }

    Ghi lên TB:
      points = "{400,89;853,61;886,358;453,393}"
    """
    if not request.is_json:
        abort(400, "Expect application/json")

    data = request.get_json(silent=True) or {}
    points = data.get("points", [])
    image = data.get("image", "")
    device_id = data.get("deviceId")
    device_name = data.get("deviceName", "")

    if not device_id:
        abort(400, "Missing 'deviceId'")

    if (
        not isinstance(points, list)
        or any(not isinstance(p, dict) or "x" not in p or "y" not in p for p in points)
    ):
        abort(400, "Invalid 'points'")

    try:
        # "x1,y1;x2,y2;..."
        loc_plain = ";".join(f"{int(p['x'])},{int(p['y'])}" for p in points)
    except Exception:
        abort(400, "Points must contain numeric x,y")

    # Chuỗi cuối cùng lưu lên TB: "{x1,y1;x2,y2;...}"
    loc_value = "{" + loc_plain + "}"

    app.logger.info(
        "Saving %d points to device %s (%s): %s -> %s",
        len(points), device_id, device_name, loc_plain, loc_value
    )

    try:
        jwt_token = _tb_login()
    except Exception as e:
        app.logger.error("ThingsBoard login failed: %s", e)
        abort(502, f"ThingsBoard login failed: {e}")

    url = _tb_shared_attr_url(device_id)
    headers = {
        "Content-Type": "application/json",
        "X-Authorization": f"Bearer {jwt_token}",
    }

    # LƯU DƯỚI DẠNG STRING
    payload = {"points": loc_value}

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        r.raise_for_status()
    except requests.RequestException as e:
        app.logger.error("ThingsBoard write failed: %s", e)
        abort(502, f"ThingsBoard write failed: {e}")

    return jsonify(
        ok=True,
        saved=len(points),
        path=f"SHARED_SCOPE/points@{device_id}",
        value=loc_value,
        image=image,
        deviceId=device_id,
        deviceName=device_name,
    )


@app.post("/reset_device")
def reset_device():
    """
    Body: {
      "deviceId": "TB device UUID",
      "deviceName": "optional"
    }

    Reset shared attribute 'points' = "{}"
    """
    if not request.is_json:
        abort(400, "Expect application/json")

    data = request.get_json(silent=True) or {}
    device_id = data.get("deviceId")
    device_name = data.get("deviceName", "")

    if not device_id:
        abort(400, "Missing 'deviceId'")

    app.logger.info("Reset points cho device %s (%s)", device_id, device_name)

    try:
        jwt_token = _tb_login()
    except Exception as e:
        app.logger.error("ThingsBoard login failed on reset: %s", e)
        abort(502, f"ThingsBoard login failed: {e}")

    url = _tb_shared_attr_url(device_id)
    headers = {
        "Content-Type": "application/json",
        "X-Authorization": f"Bearer {jwt_token}",
    }

    # Reset về chuỗi "{}" cho đồng nhất format
    payload = {"points": "{}"}

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        r.raise_for_status()
    except requests.RequestException as e:
        app.logger.error("ThingsBoard reset write failed: %s", e)
        abort(502, f"ThingsBoard reset write failed: {e}")

    return jsonify(
        ok=True,
        action="reset",
        path=f"SHARED_SCOPE/points@{device_id}",
        value="{}",
        deviceId=device_id,
        deviceName=device_name,
    )


@app.after_request
def add_embed_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        f"frame-ancestors {TB_ORIGINS}; "
        "connect-src 'self' https://*.firebasedatabase.app; "
        "img-src 'self' data: blob:;"
    )
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8008, debug=False)
