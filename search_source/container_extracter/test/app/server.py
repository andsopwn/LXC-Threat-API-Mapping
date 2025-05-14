"""
────────────────────────────────────────────────────────────────────────────
PoC Flask 서버
────────────────────────────────────────────────────────────────────────────
■ 목적
  1) requirements.txt 에 포함된 취약·비취약 라이브러리를 골고루 사용
  2) PyYAML 5.1의 RCE PoC 는 그대로 유지 (yaml.load + yaml.Loader)
  3) 그 외 라이브러리는 ‘취약 함수’를 쓰지 않고 안전하게 호출

※ 디버그 모드 ON 시 추가 위험이 있으므로 배포용에선 반드시 끄십시오.
"""

import io
import os
import json as std_json           # 표준 json
import simplejson as sjson        # 취약하지 않은 함수 사용
import urllib3                    # 외부 요청
from flask import (
    Flask, request, jsonify, render_template_string, send_file
)
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeSerializer
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import yaml                       # PoC 취약점 유지
from multipart import MultipartParser
from markupsafe import escape     # MarkupSafe 사용

app = Flask(__name__)
serializer = URLSafeSerializer("top-secret-key")

# ──────────────────────────────────────────────────────────────
# 1. 취약 YAML 파서 (PoC)
# ──────────────────────────────────────────────────────────────
@app.route("/parse", methods=["POST"])
def parse_yaml():
    """
    PoC 취약점: yaml.load(user_input, Loader=yaml.Loader)
    ─────────────────────────────────────────────────────
    payload 예시:
      !!python/object/apply:os.system ["id"]
    """
    user_input = request.data.decode("utf-8")
    try:
        parsed = yaml.load(user_input, Loader=yaml.Loader)  # 🔥 취약
        return jsonify({"status": "success", "parsed": str(parsed)})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


# ──────────────────────────────────────────────────────────────
# 2. 안전한 YAML 파서
# ──────────────────────────────────────────────────────────────
@app.route("/safe_parse", methods=["POST"])
def safe_parse_yaml():
    """yaml.safe_load 로드 (안전)"""
    try:
        data = yaml.safe_load(request.data)
        return jsonify({"safe_parsed": data})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


# ──────────────────────────────────────────────────────────────
# 3. 파일 업로드 (python-multipart + werkzeug.secure_filename)
# ──────────────────────────────────────────────────────────────
@app.route("/upload", methods=["POST"])
def upload():
    """
    raw multipart/form-data 본문을 직접 파싱해 파일 저장.
    python-multipart 의 취약 경로를 피하기 위해 secure_filename 사용.
    """
    ctype = request.headers.get("Content-Type")
    parser = MultipartParser(io.BytesIO(request.get_data()), ctype)
    for part in parser.parts():
        fname = secure_filename(part.filename or "upload.bin")
        with open(fname, "wb") as fp:
            fp.write(part.raw)
        size = os.path.getsize(fname)
        return jsonify({"saved_as": fname, "size": size})
    return jsonify({"error": "no part"}), 400


# ──────────────────────────────────────────────────────────────
# 4. 외부 GET 프록시 (urllib3)  —  SSRF 주의, host allow-list 적용
# ──────────────────────────────────────────────────────────────
ALLOWED_HOSTS = {"example.com", "httpbin.org"}

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not any(url.startswith(f"http://{h}") or url.startswith(f"https://{h}")
               for h in ALLOWED_HOSTS):
        return jsonify({"error": "host not allowed"}), 403

    http = urllib3.PoolManager()
    resp = http.request("GET", url)
    return jsonify({"status": resp.status,
                    "data": resp.data[:200].decode(errors="ignore")})


# ──────────────────────────────────────────────────────────────
# 5. 대칭 암·복호 예시 (cryptography)  —  취약 함수 미사용
# ──────────────────────────────────────────────────────────────
@app.route("/encrypt", methods=["POST"])
def encrypt():
    key = os.urandom(16)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    plaintext = request.data or b"hello"
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return send_file(io.BytesIO(ciphertext),
                     download_name="encrypted.bin",
                     mimetype="application/octet-stream")


# ──────────────────────────────────────────────────────────────
# 6. 서명/검증 (itsdangerous)
# ──────────────────────────────────────────────────────────────
@app.route("/sign")
def sign():
    msg = request.args.get("msg", "hello")
    token = serializer.dumps(msg)
    return jsonify({"token": token})

@app.route("/verify")
def verify():
    token = request.args.get("token", "")
    try:
        msg = serializer.loads(token, max_age=300)
        return jsonify({"verified": True, "message": msg})
    except Exception as exc:
        return jsonify({"verified": False, "error": str(exc)}), 400


# ──────────────────────────────────────────────────────────────
# 7. 템플릿 렌더링 (Jinja2 + MarkupSafe)
# ──────────────────────────────────────────────────────────────
@app.route("/hello")
def hello():
    user = request.args.get("name", "world")
    tpl = """
    <!doctype html><title>Hello</title>
    <h1>Hello, {{ user|e }}!</h1>
    """
    # MarkupSafe의 escape 기능 사용(`|e`)
    return render_template_string(tpl, user=escape(user))


# ──────────────────────────────────────────────────────────────
# 8. JSON 처리 (simplejson)
# ──────────────────────────────────────────────────────────────
@app.route("/json_echo", methods=["POST"])
def json_echo():
    try:
        data = sjson.loads(request.data)
        return jsonify({"echo": data})
    except sjson.JSONDecodeError:
        return jsonify({"error": "invalid json"}), 400


# ──────────────────────────────────────────────────────────────
#  메인
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # 개발 편의상 debug=True (실서비스에선 False)
    app.run(host="0.0.0.0", port=8080, debug=True)
