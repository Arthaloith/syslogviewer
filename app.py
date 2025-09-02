import os
import sys
import time
import json
from threading import Lock, Thread
from flask import Flask, render_template, jsonify, send_from_directory, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from werkzeug.security import check_password_hash
from pathlib import Path

LOG_DIR = "/var/log"
ALLOWED = {".log", ""}

# location of .auth.env created earlier
AUTH_ENV = Path(__file__).parent / ".auth.env"
FOLDER_STORE = Path(__file__).parent / ".folders.json"

app = Flask(__name__, static_folder="static", template_folder="templates")
# set a strong random secret key (or read from env)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", "replace-with-a-random-secret-please-change")
socketio = SocketIO(app, async_mode="eventlet")
thread_lock = Lock()
tail_threads = {}  # { room: {"thread": Thread, "stop": bool, "file": str} }

# load credentials
def load_auth():
    if not AUTH_ENV.exists():
        raise RuntimeError("Auth file missing: " + str(AUTH_ENV))
    data = {}
    with open(AUTH_ENV, "r") as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                data[k] = v
    return data.get("USERNAME"), data.get("PASSWORD_HASH")

AUTH_USER, AUTH_PW_HASH = load_auth()

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        if session.get("logged_in") and session.get("user") == AUTH_USER:
            return fn(*a, **kw)
        return redirect(url_for("login", next=request.path))
    return wrapper

def list_log_files():
    files = []
    try:
        for entry in os.listdir(LOG_DIR):
            path = os.path.join(LOG_DIR, entry)
            if os.path.isfile(path):
                _, ext = os.path.splitext(entry)
                if ext in ALLOWED:
                    files.append(entry)
    except Exception as e:
        print("Error listing logs:", e, file=sys.stderr)
    files.sort()
    return files

# ------------------------
# Folder (virtual) helpers
# ------------------------
def _load_folders():
    try:
        if not FOLDER_STORE.exists():
            return {}
        with open(FOLDER_STORE, "r") as fh:
            data = json.load(fh) or {}
            return {k: list(v) for k, v in data.items()}
    except Exception:
        return {}

def _save_folders(data):
    try:
        with open(FOLDER_STORE, "w") as fh:
            json.dump(data, fh, indent=2)
        return True
    except Exception:
        return False

def _sanitize_filename(fname):
    # only allow basename (no slashes) and allowed extension
    if os.path.basename(fname) != fname:
        return None
    _, ext = os.path.splitext(fname)
    if ext not in ALLOWED:
        return None
    return fname

# ------------------------
# Log tailing helpers
# ------------------------
def send_last_lines(filename, room, n=200):
    path = os.path.join(LOG_DIR, filename)
    try:
        with open(path, "r", errors="replace") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = 4096
            data = ""
            while len(data.splitlines()) <= n and size > 0:
                size = max(0, size - block)
                fh.seek(size)
                data = fh.read()
            lines = data.splitlines()[-n:]
            for line in lines:
                socketio.emit("log_line", {"file": filename, "line": line + "\n"}, room=room)
    except Exception as e:
        socketio.emit("log_error", {"file": filename, "error": str(e)}, room=room)

def tail_file_background(filename, room):
    path = os.path.join(LOG_DIR, filename)
    try:
        with open(path, "r", errors="replace") as fh:
            fh.seek(0, os.SEEK_END)
            while True:
                with thread_lock:
                    info = tail_threads.get(room)
                    if not info or info.get("stop"):
                        break
                line = fh.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                socketio.emit("log_line", {"file": filename, "line": line}, room=room)
    except Exception as e:
        socketio.emit("log_error", {"file": filename, "error": str(e)}, room=room)
    finally:
        # cleanup after stop
        with thread_lock:
            if room in tail_threads:
                tail_threads.pop(room, None)

# ------------------------
# Flask routes
# ------------------------
@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        if user == AUTH_USER and check_password_hash(AUTH_PW_HASH, pw):
            session.clear()
            session["logged_in"] = True
            session["user"] = user
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        flash("Invalid credentials", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# Return grouped file list (folders + unsorted)
@app.route("/logs/list")
@login_required
def logs_list():
    files = list_log_files()
    folders = _load_folders()
    # prune folder entries referencing missing files
    for k in list(folders.keys()):
        folders[k] = [f for f in folders[k] if f in files]
    # create response: {"folders": {name: [files]}, "unsorted": [files not in any folder]}
    assigned = set()
    for v in folders.values():
        assigned.update(v)
    unsorted = [f for f in files if f not in assigned]
    return jsonify({"folders": folders, "unsorted": unsorted})

@app.route("/static/<path:filename>")
@login_required
def static_files(filename):
    return send_from_directory("static", filename)

# Folder management APIs
@app.route("/folders/list")
@login_required
def folders_list():
    folders = _load_folders()
    return jsonify(folders)

@app.route("/folders/create", methods=["POST"])
@login_required
def folders_create():
    name = (request.json or {}).get("name", "")
    if not name or "/" in name or "\\" in name:
        return jsonify({"error": "invalid folder name"}), 400
    folders = _load_folders()
    if name in folders:
        return jsonify({"error": "exists"}), 400
    folders[name] = []
    _save_folders(folders)
    return jsonify({"ok": True})

@app.route("/folders/delete", methods=["POST"])
@login_required
def folders_delete():
    name = (request.json or {}).get("name", "")
    folders = _load_folders()
    if name not in folders:
        return jsonify({"error": "not found"}), 404
    folders.pop(name, None)
    _save_folders(folders)
    return jsonify({"ok": True})

@app.route("/folders/move", methods=["POST"])
@login_required
def folders_move():
    # move file -> target_folder (or "" for Unsorted)
    body = request.json or {}
    file = body.get("file", "")
    target = body.get("target", "")
    file = _sanitize_filename(file)
    if not file:
        return jsonify({"error": "invalid file"}), 400
    # ensure file exists on disk and allowed
    path = os.path.join(LOG_DIR, file)
    if not os.path.isfile(path):
        return jsonify({"error": "file not found"}), 404
    folders = _load_folders()
    # remove file from any folder
    for k in list(folders.keys()):
        if file in folders[k]:
            folders[k].remove(file)
    if target:
        if target not in folders:
            return jsonify({"error": "target folder not found"}), 404
        if file not in folders[target]:
            folders[target].append(file)
    _save_folders(folders)
    return jsonify({"ok": True})

# ------------------------
# Socket.IO handlers
# ------------------------
@socketio.on("connect")
def ws_connect():
    # only allow socket if session shows logged_in
    if not session.get("logged_in") or session.get("user") != AUTH_USER:
        # disconnect unauthenticated sockets
        disconnect()
        return
    emit("connected", {"msg": "connected"})

@socketio.on("join")
def on_join(data):
    filename = data.get("file")
    if not filename:
        return
    room = filename
    join_room(room)
    emit("joined", {"file": filename})
    send_last_lines(filename, room, n=200)

    with thread_lock:
        # stop any existing thread for this room
        old = tail_threads.get(room)
        if old:
            old["stop"] = True
        # create a fresh one
        tail_threads[room] = {"thread": None, "stop": False, "file": filename}
        thread = Thread(target=tail_file_background, args=(filename, room), daemon=True)
        tail_threads[room]["thread"] = thread
        thread.start()

@socketio.on("leave")
def on_leave(data):
    filename = data.get("file")
    if not filename:
        return
    room = filename
    leave_room(room)
    with thread_lock:
        info = tail_threads.get(room)
        if info:
            info["stop"] = True

@socketio.on("disconnect")
def on_disconnect():
    pass

if __name__ == "__main__":
    host = "0.0.0.0"
    port = 5065
    print(f"Serving on http://{host}:{port}")
    socketio.run(app, host=host, port=port)
