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
DEFAULT_SEED_FILE = BASE_DIR / "hr_plans_backup_2026-11-23.json"

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# 跨裝置／行動裝置常見情境下，若使用 HTTPS 建議開啟 Secure Cookie；本機或 HTTP 測試時自動相容
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("FORCE_SECURE_COOKIE", "").lower() == "true":
    app.config["SESSION_COOKIE_SECURE"] = True


def load_admin_credentials() -> dict[str, str]:
    """
    載入管理者帳密（支援環境變數 ADMIN_ACCOUNTS_JSON 或預設帳號）。
    格式範例：{"admin": "your-password", "hr_lead": "another-password"}
    """
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


def seed_initial_data() -> dict[str, Any]:
    """若尚無 plans_data.json，嘗試從預設備份檔建立初始資料。"""
    if DEFAULT_SEED_FILE.exists():
        try:
            with DEFAULT_SEED_FILE.open("r", encoding="utf-8") as f:
                content = json.load(f)
            if isinstance(content, dict) and isinstance(content.get("plans"), list):
                return content
            if isinstance(content, list):
                return {"plans": content, "customCodes": {}}
        except Exception as exc:
            app.logger.warning("讀取預設備份檔失敗: %s", exc)

    return {"plans": [], "customCodes": {}}


def read_store() -> dict[str, Any]:
    """安全讀取伺服器端儲存的計畫資料。"""
    if not DATA_FILE.exists():
        initial = seed_initial_data()
        write_store(initial)
        return initial

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

    return seed_initial_data()


def write_store(payload: dict[str, Any]) -> None:
    """以原子寫入方式更新伺服器端 JSON 檔案，避免同時寫入造成毀損。"""
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp_file = DATA_FILE.with_suffix(".json.tmp")
    with tmp_file.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    tmp_file.replace(DATA_FILE)


def login_required(fn):
    """驗證目前 Session 是否為已登入管理者。"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        admin_user = session.get("admin_user")
        if not admin_user:
            return jsonify({"ok": False, "message": "請先以管理者帳號密碼登入後再進行修改。"}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
def serve_index():
    """提供主前端頁面。"""
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/auth/status")
def auth_status():
    """查詢目前登入狀態。"""
    admin_user = session.get("admin_user")
    return jsonify({
        "ok": True,
        "authenticated": bool(admin_user),
        "username": admin_user or ""
    })


@app.post("/api/auth/login")
def auth_login():
    """管理者帳密登入。"""
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
    """管理者登出。"""
    session.pop("admin_user", None)
    return jsonify({"ok": True, "message": "已登出管理者帳號。"})


@app.get("/api/plans")
def get_plans():
    """取得最新計畫資料（任何裝置均可讀取）。"""
    store = read_store()
    return jsonify({
        "ok": True,
        "plans": store.get("plans", []),
        "customCodes": store.get("customCodes", {})
    })


@app.put("/api/plans")
@login_required
def update_plans():
    """儲存所有計畫與自訂編號（需管理者登入）。"""
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
    """更新單筆計畫內容（需管理者登入）。"""
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
    app.logger.exception("未預期錯誤: %s", exc)
    return jsonify({"ok": False, "message": "伺服器發生未預期錯誤。"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False)