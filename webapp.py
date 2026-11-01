from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename


ROOT = Path(__file__).parent
DATA = ROOT / "app_data"
FILES = DATA / "files"
STATE = DATA / "state.json"
ALLOWED = {"pdf", "docx", "pptx", "ppt", "txt", "md", "png", "jpg", "jpeg"}

app = Flask(__name__, template_folder="web_templates", static_folder="web_static")


def now() -> str:
    return datetime.now().strftime("%d-%m-%Y %H:%M")


def clean_name(value: str) -> str:
    name = secure_filename(Path(value).name).strip(" .")
    return name or "bestand"


def default_state() -> dict:
    chat_id = str(uuid.uuid4())
    return {
        "active_chat": chat_id,
        "chats": [{"id": chat_id, "title": "Nieuwe chat", "updated": now(), "messages": []}],
        "folders": [{"id": "root", "name": "Mijn bestanden", "parent": None}],
        "files": [],
    }


def load_state() -> dict:
    DATA.mkdir(exist_ok=True)
    FILES.mkdir(exist_ok=True)
    if STATE.exists():
        try:
            state = json.loads(STATE.read_text(encoding="utf-8"))
            old = {"presentaties", "lesmateriaal"}
            state["folders"] = [f for f in state.get("folders", []) if f.get("id") not in old]
            if not any(f.get("id") == "root" for f in state["folders"]):
                state["folders"].insert(0, {"id": "root", "name": "Mijn bestanden", "parent": None})
            save_state(state)
            return state
        except (OSError, json.JSONDecodeError):
            pass
    state = default_state()
    save_state(state)
    return state


def save_state(state: dict) -> None:
    DATA.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def find(items: list[dict], item_id: str) -> dict | None:
    return next((item for item in items if item.get("id") == item_id), None)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/state")
def api_state():
    return jsonify(load_state())


@app.post("/api/chats")
def create_chat():
    state = load_state()
    empty = next((c for c in state["chats"] if c["title"] == "Nieuwe chat" and not c["messages"]), None)
    if not empty:
        empty = {"id": str(uuid.uuid4()), "title": "Nieuwe chat", "updated": now(), "messages": []}
        state["chats"].insert(0, empty)
    state["active_chat"] = empty["id"]
    save_state(state)
    return jsonify(empty)


@app.patch("/api/chats/<chat_id>")
def edit_chat(chat_id):
    state = load_state(); chat = find(state["chats"], chat_id)
    if not chat: return jsonify(error="Chat niet gevonden"), 404
    title = str(request.json.get("title", "")).strip()
    if title: chat["title"] = title; chat["updated"] = now()
    if isinstance(request.json.get("messages"), list): chat["messages"] = request.json["messages"]; chat["updated"] = now()
    save_state(state); return jsonify(chat)


@app.delete("/api/chats/<chat_id>")
def delete_chat(chat_id):
    state = load_state(); state["chats"] = [c for c in state["chats"] if c["id"] != chat_id]
    if not state["chats"]: state["chats"] = default_state()["chats"]
    if state["active_chat"] == chat_id: state["active_chat"] = state["chats"][0]["id"]
    save_state(state); return jsonify(state)


@app.post("/api/folders")
def create_folder():
    state = load_state(); body = request.json or {}; name = str(body.get("name", "")).strip()
    parent = body.get("parent") or "root"
    if not name: return jsonify(error="Geef een naam op"), 400
    folder = {"id": str(uuid.uuid4()), "name": name, "parent": parent}
    state["folders"].append(folder); save_state(state); return jsonify(folder)


@app.patch("/api/folders/<folder_id>")
def edit_folder(folder_id):
    state = load_state(); folder = find(state["folders"], folder_id)
    if not folder or folder_id == "root": return jsonify(error="Map niet gevonden"), 404
    name = str((request.json or {}).get("name", "")).strip()
    if name: folder["name"] = name
    save_state(state); return jsonify(folder)


@app.delete("/api/folders/<folder_id>")
def delete_folder(folder_id):
    state = load_state(); folder = find(state["folders"], folder_id)
    if not folder or folder_id == "root": return jsonify(error="Map niet gevonden"), 404
    remove = {folder_id}; changed = True
    while changed:
        changed = False
        for candidate in state["folders"]:
            if candidate.get("parent") in remove and candidate["id"] not in remove:
                remove.add(candidate["id"]); changed = True
    for file in [f for f in state["files"] if f.get("folder") in remove]:
        path = Path(file.get("path", ""))
        if path.exists(): path.unlink()
    state["files"] = [f for f in state["files"] if f.get("folder") not in remove]
    state["folders"] = [f for f in state["folders"] if f.get("id") not in remove]
    save_state(state); return jsonify(state)


@app.post("/api/files")
def upload_files():
    state = load_state(); folder = request.form.get("folder", "root")
    target = FILES / folder; target.mkdir(parents=True, exist_ok=True)
    created = []
    for uploaded in request.files.getlist("files"):
        name = clean_name(uploaded.filename or "bestand")
        if Path(name).suffix.lower().lstrip(".") not in ALLOWED: continue
        path = target / name; uploaded.save(path)
        info = {"id": str(uuid.uuid4()), "name": name, "folder": folder, "path": str(path), "size": path.stat().st_size, "added": now()}
        state["files"].append(info); created.append(info)
    save_state(state); return jsonify(created)


@app.patch("/api/files/<file_id>")
def edit_file(file_id):
    state = load_state(); file = find(state["files"], file_id)
    if not file: return jsonify(error="Bestand niet gevonden"), 404
    body = request.json or {}; old_path = Path(file["path"])
    if body.get("name"):
        name = clean_name(str(body["name"])); new_path = old_path.with_name(name)
        if old_path.exists() and new_path != old_path: old_path.rename(new_path)
        file["name"] = name; file["path"] = str(new_path)
    if body.get("folder") and body["folder"] != file["folder"]:
        target = FILES / body["folder"]; target.mkdir(parents=True, exist_ok=True); new_path = target / file["name"]
        if old_path.exists(): old_path.rename(new_path)
        file["folder"] = body["folder"]; file["path"] = str(new_path)
    save_state(state); return jsonify(file)


@app.delete("/api/files/<file_id>")
def delete_file(file_id):
    state = load_state(); file = find(state["files"], file_id)
    if not file: return jsonify(error="Bestand niet gevonden"), 404
    path = Path(file.get("path", ""))
    if path.exists(): path.unlink()
    state["files"] = [f for f in state["files"] if f["id"] != file_id]
    save_state(state); return jsonify(state)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8501, debug=True)
