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

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# 設為 true 時，每次部署重啟會清空舊的 plans_data.json，讓前端 index.html 內建的最新 1~37 筆資料直接生效；
# 若之後要在線上後台手動新增/修改並永久保留，可在 Render 環境變數設 USE_INDEX_DEFAULT_ON_BOOT=false
USE_INDEX_DEFAULT_ON_BOOT = os.environ.get("USE_INDEX_DEFAULT_ON_BOOT", "true").strip().lower() != "false"

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("FORCE_SECURE_COOKIE", "").lower() == "true":
    app.config["SESSION_COOKIE_SECURE"] = True


def load_admin_credentials() -> dict[str, str]:
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
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp_file = DATA_FILE.with_suffix(".json.tmp")
    with tmp_file.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    tmp_file.replace(DATA_FILE)


def sync_store_on_startup() -> dict[str, Any]:
    """
    啟動時若 USE_INDEX_DEFAULT_ON_BOOT=true，回傳空陣列並重置 plans_data.json，
    讓前端 index.html 直接載入內建的最新 1～37 號資料，不再被舊的 hr_plans_backup_2026-11-23.json 覆蓋！
    """
    if USE_INDEX_DEFAULT_ON_BOOT or not DATA_FILE.exists():
        empty_payload = {"plans": [], "customCodes": {}}
        try:
            write_store(empty_payload)
        except Exception as exc:
            app.logger.warning("重置 plans_data.json 失敗: %s", exc)
        return empty_payload

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

    return {"plans": [], "customCodes": {}}


def read_store() -> dict[str, Any]:
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

    return {"plans": [], "customCodes": {}}


sync_store_on_startup()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        admin_user = session.get("admin_user")
        if not admin_user:
            return jsonify({"ok": False, "message": "請先以管理者帳號密碼登入後再進行修改。"}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
def serve_index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/auth/status")
def auth_status():
    admin_user = session.get("admin_user")
    return jsonify({
        "ok": True,
        "authenticated": bool(admin_user),
        "username": admin_user or ""
    })


@app.post("/api/auth/login")
def auth_login():
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
    session.pop("admin_user", None)
    return jsonify({"ok": True, "message": "已登出管理者帳號。"})


@app.get("/api/plans")
def get_plans():
    store = read_store()
    return jsonify({
        "ok": True,
        "plans": store.get("plans", []),
        "customCodes": store.get("customCodes", {})
    })


@app.put("/api/plans")
@login_required
def update_plans():
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
