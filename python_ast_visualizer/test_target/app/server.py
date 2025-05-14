"""
────────────────────────────────────────────────────────────────────────────
PoC Flask 서버 – 복잡 버전
────────────────────────────────────────────────────────────────────────────
■ 목적
  1) requirements.txt 에 포함된 취약·비취약 라이브러리를 골고루 사용
  2) PyYAML 5.1의 RCE PoC 는 그대로 유지 (yaml.load + yaml.Loader)
  3) 그 외 라이브러리는 ‘취약 함수’를 쓰지 않고 안전하게 호출

※ 디버그 모드 ON 시 추가 위험이 있으므로 배포용에선 반드시 끄십시오.
"""

import io
import os
import json as std_json
import simplejson as sjson
import urllib3
from flask import Flask, request, jsonify, render_template_string, send_file
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeSerializer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import yaml                       # PoC 취약점 유지
from multipart import MultipartParser
from markupsafe import escape

app = Flask(__name__)
serializer = URLSafeSerializer("top-secret-key")

# ──────────────────────────────────────────────────────────────
# 1. PoC 취약 YAML 파서 (외부 접근 가능)
# ──────────────────────────────────────────────────────────────
@app.route("/parse", methods=["POST"])
def parse_yaml():
    data = request.data.decode()
    return _external_load(data)

@app.route("/admin_parse", methods=["POST"])
def admin_parse():
    data = request.args.get("data", "")
    try:
        return jsonify(_external_load(data))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ──────────────────────────────────────────────────────────────
# 2. 안전한 YAML 파서 (외부 접근 가능)
# ──────────────────────────────────────────────────────────────
@app.route("/safe_parse", methods=["POST"])
def safe_parse():
    return jsonify({"safe": yaml.safe_load(request.data)})

# ──────────────────────────────────────────────────────────────
# 3. 파일 업로드 (외부 접근 가능)
# ──────────────────────────────────────────────────────────────
@app.route("/upload", methods=["POST"])
def upload():
    ctype = request.headers.get("Content-Type")
    parser = MultipartParser(io.BytesIO(request.get_data()), ctype)
    for part in parser.parts():
        name = secure_filename(part.filename or "upload.bin")
        with open(name, "wb") as f:
            f.write(part.raw)
        return jsonify({"file": name, "size": os.path.getsize(name)})
    return jsonify({"error": "no part"}), 400

@app.route("/upload_parse", methods=["POST"])
def upload_parse():
    ctype = request.headers.get("Content-Type")
    parser = MultipartParser(io.BytesIO(request.get_data()), ctype)
    for part in parser.parts():
        name = secure_filename(part.filename or "upload.bin")
        with open(name, "wb") as f:
            f.write(part.raw)
        try:
            parsed = _internal_stage_one(name)
            return jsonify(parsed)
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    return jsonify({"error": "no part"}), 400

# ──────────────────────────────────────────────────────────────
# 4. 외부 GET 프록시 (외부 접근 가능)
# ──────────────────────────────────────────────────────────────
ALLOWED = {"example.com", "httpbin.org"}

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not any(url.startswith(f"http://{h}") for h in ALLOWED):
        return jsonify({"error": "blocked"}), 403
    http = urllib3.PoolManager()
    resp = http.request("GET", url)
    return jsonify({"status": resp.status, "body": resp.data[:50].decode(errors="ignore")})

# ──────────────────────────────────────────────────────────────
# 5. 암호화 & 서명/검증 (외부 접근 가능)
# ──────────────────────────────────────────────────────────────
@app.route("/encrypt", methods=["POST"])
def encrypt():
    key, iv = os.urandom(16), os.urandom(16)
    cip = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    ct = cip.encryptor().update(request.data or b"") + cip.encryptor().finalize()
    return send_file(io.BytesIO(ct), download_name="ct.bin", mimetype="application/octet-stream")

@app.route("/sign")
def sign():
    token = serializer.dumps(request.args.get("msg", "x"))
    return jsonify({"token": token})

@app.route("/verify")
def verify():
    try:
        msg = serializer.loads(request.args.get("token", ""), max_age=60)
        return jsonify({"ok": True, "msg": msg})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

# ──────────────────────────────────────────────────────────────
# 6. 템플릿 & JSON 처리 (외부 접근 가능)
# ──────────────────────────────────────────────────────────────
@app.route("/hello")
def hello():
    user = escape(request.args.get("name", "guest"))
    return render_template_string(f"<h1>Hello, {user}!</h1>")

@app.route("/json_echo", methods=["POST"])
def json_echo():
    try:
        return jsonify({"echo": sjson.loads(request.data)})
    except Exception:
        return jsonify({"error": "bad json"}), 400

# ──────────────────────────────────────────────────────────────
# ✨ 내부 전용 YAML 로더 함수 (외부 접근 불가)
# ──────────────────────────────────────────────────────────────
def _static_one():
    const = "one: 1\ntwo: 2"
    return yaml.load(const, Loader=yaml.Loader)

def _static_two():
    with open("static.yaml") as f:
        return yaml.load(f.read(), Loader=yaml.Loader)

def _static_three():
    arr = ["a: 1", "b: 2", "c: 3"]
    return yaml.load("\n".join(arr), Loader=yaml.Loader)

def _static_four():
    data = {"x": 10, "y": 20}
    dumped = std_json.dumps(data)
    return yaml.load(dumped.replace("{", "").replace("}", ""), Loader=yaml.Loader)

def _static_five():
    text = "\n".join([f"n{i}: {i}" for i in range(3)])
    return yaml.load(text, Loader=yaml.Loader)

# ──────────────────────────────────────────────────────────────
# ✨ 내부 전용 복합 로더 클래스 (외부 접근 불가)
# ──────────────────────────────────────────────────────────────
class _InternalCombiner:
    def __init__(self, files):
        self.files = files

    def combined(self):
        snippets = []
        for path in self.files:
            with open(path) as f:
                snippets.append(f.read())
        text = "\n---\n".join(snippets)
        return yaml.load(text, Loader=yaml.Loader)

# ──────────────────────────────────────────────────────────────
# ✨ 외부 호출용 공통 함수
# ──────────────────────────────────────────────────────────────
def _external_load(txt):
    return {"parsed": yaml.load(txt, Loader=yaml.Loader)}

# ──────────────────────────────────────────────────────────────
# ✨ 내부 전용 파일 로더 체인 함수 (외부 접근 불가)
# ──────────────────────────────────────────────────────────────
def _internal_stage_one(path):
    with open(path) as f:
        content = f.read()
    return _internal_stage_two(content)

def _internal_stage_two(txt):
    return _external_load(txt)

# ──────────────────────────────────────────────────────────────
# 메인
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # debug=True → 위험!
    app.run(host="0.0.0.0", port=8080, debug=True)
