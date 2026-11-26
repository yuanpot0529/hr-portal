from __future__ import annotations

import json
import os
import secrets
from functools import wraps
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "plans_data.json"
SEED_FILE = BASE_DIR / "hr_plans_backup_2026-11-23.json"

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# 預設以種子檔同步初始化資料；若希望保留伺服器上已手動修改的 plans_data.json，可設環境變數 FORCE_SYNC_FROM_SEED=false
FORCE_SYNC_FROM_SEED = os.environ.get("FORCE_SYNC_FROM_SEED", "true").strip().lower() != "false"

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("FORCE_SECURE_COOKIE", "").lower() == "true":
    app.config["SESSION_COOKIE_SECURE"] = True


def load_admin_credentials() -> dict[str, str]:
    """載入管理者帳號與密碼雜湊，支援環境變數設定或預設帳號。"""
    raw_json = os.environ.get("ADMIN_ACCOUNTS_JSON", "").strip()
    accounts: dict[str, str] = {}

    if raw_json:
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, dict):
                for username, password in parsed.items():
                    if isinstance(username, str) and isinstance(password, str) and username.strip() and password:
                        accounts[username.strip()] = generate_password_hash(password)
        except json.JSONDecodeError:
            app.logger.warning("ADMIN_ACCOUNTS_JSON 格式無效，改用預設管理者帳密。")

    if not accounts:
        default_user = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
        default_pass = os.environ.get("ADMIN_PASSWORD", "hr2026admin")
        accounts[default_user] = generate_password_hash(default_pass)

    return accounts


ADMIN_HASHES = load_admin_credentials()


def write_store(payload: dict[str, Any]) -> None:
    """以暫存檔原子替換方式寫入 plans_data.json，避免寫入中斷造成檔案損毀。"""
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp_file = DATA_FILE.with_suffix(".json.tmp")
    with tmp_file.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    tmp_file.replace(DATA_FILE)


def load_seed_payload() -> dict[str, Any]:
    """讀取種子備份檔，若檔案不存在或格式異常則回傳空結構。"""
    if SEED_FILE.exists():
        try:
            with SEED_FILE.open("r", encoding="utf-8") as f:
                seed = json.load(f)
            if isinstance(seed, list):
                return {"plans": seed, "customCodes": {}}
            if isinstance(seed, dict):
                plans = seed.get("plans", [])
                custom_codes = seed.get("customCodes", {})
                if isinstance(plans, list):
                    return {
                        "plans": plans,
                        "customCodes": custom_codes if isinstance(custom_codes, dict) else {}
                    }
        except Exception as exc:
            app.logger.error("讀取初始種子資料檔失敗: %s", exc)
    return {"plans": [], "customCodes": {}}


def sync_store_on_startup() -> dict[str, Any]:
    """啟動時依 FORCE_SYNC_FROM_SEED 決定是否以種子檔同步 plans_data.json。"""
    if FORCE_SYNC_FROM_SEED or not DATA_FILE.exists():
        seed_payload = load_seed_payload()
        try:
            write_store(seed_payload)
        except Exception as exc:
            app.logger.warning("寫入 plans_data.json 失敗: %s", exc)
        return seed_payload

    try:
        with DATA_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return {"plans": data, "customCodes": {}}
        if isinstance(data, dict):
            if not isinstance(data.get("plans"), list):
                data["plans"] = []
            if not isinstance(data.get("customCodes"), dict):
                data["customCodes"] = {}
            return data
    except Exception as exc:
        app.logger.error("讀取 plans_data.json 失敗: %s", exc)

    return load_seed_payload()


def read_store() -> dict[str, Any]:
    """讀取目前伺服器端的計畫資料與自訂編號設定。"""
    if not DATA_FILE.exists():
        return sync_store_on_startup()

    try:
        with DATA_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return {"plans": data, "customCodes": {}}
        if isinstance(data, dict):
            if not isinstance(data.get("plans"), list):
                data["plans"] = []
            if not isinstance(data.get("customCodes"), dict):
                data["customCodes"] = {}
            return data
    except Exception as exc:
        app.logger.error("讀取 plans_data.json 失敗: %s", exc)

    return load_seed_payload()


sync_store_on_startup()


def login_required(fn):
    """驗證管理者登入狀態的裝飾器。"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        admin_user = session.get("admin_user")
        if not admin_user:
            return jsonify({"ok": False, "message": "請先以管理者帳號密碼登入後再進行修改。"}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
def serve_index():
    """回傳前端單頁應用程式 index.html。"""
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/auth/status")
def auth_status():
    """查詢目前 session 是否已登入管理者帳號。"""
    admin_user = session.get("admin_user")
    return jsonify({
        "ok": True,
        "authenticated": bool(admin_user),
        "username": admin_user or ""
    })


@app.post("/api/auth/login")
def auth_login():
    """驗證管理者帳號密碼並建立登入 session。"""
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))

    pw_hash = ADMIN_HASHES.get(username)
    if not pw_hash or not password or not check_password_hash(pw_hash, password):
        return jsonify({"ok": False, "message": "管理者帳號或密碼錯誤。"}), 401

    session["admin_user"] = username
    return jsonify({
        "ok": True,
        "message": f"歡迎登入，{username}",
        "username": username
    })


@app.post("/api/auth/logout")
def auth_logout():
    """清除管理者登入 session。"""
    session.pop("admin_user", None)
    return jsonify({"ok": True, "message": "已登出管理者帳號。"})


@app.get("/api/plans")
def get_plans():
    """取得完整計畫清單與自訂編號。"""
    store = read_store()
    return jsonify({
        "ok": True,
        "plans": store.get("plans", []),
        "customCodes": store.get("customCodes", {})
    })


@app.put("/api/plans")
@login_required
def update_plans():
    """整批更新計畫清單與自訂編號並同步寫入磁碟。"""
    body = request.get_json(silent=True) or {}
    plans = body.get("plans")
    custom_codes = body.get("customCodes", {})

    if not isinstance(plans, list):
        return jsonify({"ok": False, "message": "plans 必須為陣列格式。"}), 400
    if not isinstance(custom_codes, dict):
        return jsonify({"ok": False, "message": "customCodes 必須為物件格式。"}), 400

    payload = {
        "plans": plans,
        "customCodes": custom_codes
    }
    try:
        write_store(payload)
    except Exception as exc:
        app.logger.error("寫入 plans_data.json 失敗: %s", exc)
        return jsonify({"ok": False, "message": "伺服器儲存資料失敗。"}), 500

    return jsonify({
        "ok": True,
        "message": f"已同步更新 {len(plans)} 筆計畫至伺服器（操作者：{session.get('admin_user')}）。"
    })


@app.put("/api/plans/<plan_id>")
@login_required
def update_single_plan(plan_id: str):
    """更新或新增單筆計畫資料並寫入磁碟。"""
    body = request.get_json(silent=True) or {}
    updated_plan = body.get("plan")
    if not isinstance(updated_plan, dict):
        return jsonify({"ok": False, "message": "缺少有效的計畫資料。"}), 400

    store = read_store()
    plans: list[dict[str, Any]] = store.get("plans", [])
    found = False

    for idx, item in enumerate(plans):
        if isinstance(item, dict) and str(item.get("id")) == plan_id:
            updated_plan["id"] = plan_id
            plans[idx] = updated_plan
            found = True
            break

    if not found:
        updated_plan["id"] = plan_id
        plans.append(updated_plan)

    store["plans"] = plans
    try:
        write_store(store)
    except Exception as exc:
        app.logger.error("更新單筆計畫失敗: %s", exc)
        return jsonify({"ok": False, "message": "伺服器儲存資料失敗。"}), 500

    return jsonify({
        "ok": True,
        "message": f"已儲存計畫「{updated_plan.get('title', plan_id)}」，所有裝置已同步。",
        "plan": updated_plan
    })


@app.errorhandler(Exception)
def handle_unexpected_error(exc):
    """捕捉未預期例外並回傳標準 JSON 錯誤訊息。"""
    app.logger.exception("未預期錯誤: %s", exc)
    return jsonify({"ok": False, "message": "伺服器發生未預期錯誤。"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False)
