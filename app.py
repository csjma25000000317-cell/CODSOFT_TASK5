
import os
import re
import hmac
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
STORAGE = os.path.join(BASE_DIR, "private_storage")
DB_PATH = os.path.join(BASE_DIR, "vault.db")
KEY_PATH = os.path.join(BASE_DIR, "secret.key")

os.makedirs(STORAGE, exist_ok=True)

app = Flask(__name__)

SECRET_PATH = os.path.join(BASE_DIR, ".flask_secret")

def load_secret_key():
    env_key = os.environ.get("FLASK_SECRET_KEY")
    if env_key:
        return env_key

    try:
        with open(SECRET_PATH, "x", encoding="utf-8") as secret_file:
            secret_file.write(secrets.token_hex(32))
    except FileExistsError:
        pass

    with open(SECRET_PATH, "r", encoding="utf-8") as secret_file:
        return secret_file.read().strip()

app.secret_key = load_secret_key()
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
)

ALLOWED_EXTENSIONS = {
    "pdf", "txt", "png", "jpg", "jpeg",
    "docx", "xlsx", "csv", "pptx", "zip", "py"
}


def get_cipher():
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "xb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_PATH, "rb") as f:
        return Fernet(f.read().strip())


cipher = get_cipher()


def now():
    return datetime.now(timezone.utc)


def connect_db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    with connect_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                active INTEGER NOT NULL DEFAULT 1
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                created TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires TEXT NOT NULL,
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
            )
        """)

        # Support a database created by an earlier version of this project.
        columns = {
            row["name"] for row in con.execute("PRAGMA table_info(users)")
        }
        if "active" not in columns:
            con.execute(
                "ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1"
            )


def valid_username(username):
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,30}", username))


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with connect_db() as con:
        user = con.execute(
            "SELECT id, username, role, active FROM users WHERE id=?",
            (user_id,)
        ).fetchone()
    if not user or not user["active"]:
        session.clear()
        return None
    return user


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def file_for_user(file_id):
    user = current_user()
    with connect_db() as con:
        record = con.execute(
            "SELECT * FROM files WHERE id=?", (file_id,)
        ).fetchone()
    if not record:
        abort(404)
    if user["role"] != "admin" and record["owner_id"] != user["id"]:
        abort(403)
    return record


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/setup-admin", methods=["GET", "POST"])
def setup_admin():
    with connect_db() as con:
        count = con.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role='admin'"
        ).fetchone()["n"]

    if count:
        abort(404)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not valid_username(username):
            flash("Use 3–30 letters, numbers or underscores for username.", "danger")
        elif len(password) < 12:
            flash("Admin password must contain at least 12 characters.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            try:
                with connect_db() as con:
                    con.execute(
                        "INSERT INTO users(username,password,role,active) VALUES(?,?,?,1)",
                        (username, generate_password_hash(password), "admin")
                    )
                flash("Admin account created. Please sign in.", "success")
                return redirect(url_for("admin_login"))
            except sqlite3.IntegrityError:
                flash("That username is already in use.", "danger")

    return render_template("auth.html", mode="setup_admin")


def authenticate(username, password, required_role):
    with connect_db() as con:
        user = con.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()

    if (
        user
        and user["active"]
        and user["role"] == required_role
        and check_password_hash(user["password"], password)
    ):
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session.permanent = True
        return True
    
    return False


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if authenticate(username, password, "user"):
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid public-user credentials.", "danger")
    return render_template("auth.html", mode="login")


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if authenticate(username, password, "admin"):
            flash("Admin sign-in successful.", "success")
            return redirect(url_for("admin"))
        flash("Invalid admin credentials.", "danger")
    return render_template("auth.html", mode="admin_login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not valid_username(username):
            flash("Use 3–30 letters, numbers or underscores.", "danger")
        elif len(password) < 10:
            flash("Password must contain at least 10 characters.", "danger")
        else:
            try:
                with connect_db() as con:
                    con.execute(
                        "INSERT INTO users(username,password,role,active) VALUES(?,?,?,1)",
                        (username, generate_password_hash(password), "user")
                    )
                flash("Account created. You can now sign in anytime.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username already exists. Please sign in instead.", "danger")
    return render_template("auth.html", mode="register")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have signed out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    with connect_db() as con:
        if user["role"] == "admin":
            files = con.execute("""
                SELECT files.*, users.username AS owner
                FROM files JOIN users ON users.id=files.owner_id
                ORDER BY files.id DESC
            """).fetchall()
        else:
            files = con.execute("""
                SELECT files.*, users.username AS owner
                FROM files JOIN users ON users.id=files.owner_id
                WHERE files.owner_id=? ORDER BY files.id DESC
            """, (user["id"],)).fetchall()

        shares = con.execute("""
            SELECT shares.*, files.filename
            FROM shares JOIN files ON files.id=shares.file_id
            WHERE files.owner_id=? ORDER BY shares.id DESC
        """, (user["id"],)).fetchall()

    return render_template("dashboard.html", files=files, shares=shares, max_mb=20)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Choose a file first.", "danger")
        return redirect(url_for("dashboard"))

    filename = secure_filename(uploaded.filename)
    if not filename or not allowed_file(filename):
        flash("File type is not allowed.", "danger")
        return redirect(url_for("dashboard"))

    data = uploaded.read(20 * 1024 * 1024 + 1)
    if not data or len(data) > 20 * 1024 * 1024:
        flash("Choose a non-empty file smaller than 20 MB.", "danger")
        return redirect(url_for("dashboard"))

    stored_name = secrets.token_hex(24) + ".enc"
    path = os.path.join(STORAGE, stored_name)

    try:
        encrypted = cipher.encrypt(data)
        with open(path, "xb") as output:
            output.write(encrypted)
        with connect_db() as con:
            con.execute("""
                INSERT INTO files(owner_id,filename,stored_name,size,created)
                VALUES(?,?,?,?,?)
            """, (session["user_id"], filename, stored_name, len(data), now().isoformat()))
        flash("File encrypted and uploaded.", "success")
    except Exception:
        app.logger.exception("Upload failed")
        if os.path.exists(path):
            os.remove(path)
        flash("Upload failed. Check the VS Code terminal.", "danger")

    return redirect(url_for("dashboard"))


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    record = file_for_user(file_id)
    try:
        with open(os.path.join(STORAGE, record["stored_name"]), "rb") as source:
            data = cipher.decrypt(source.read())
        return send_file(BytesIO(data), as_attachment=True, download_name=record["filename"])
    except (OSError, InvalidToken):
        app.logger.exception("Download/decryption failed")
        flash("File could not be decrypted.", "danger")
        return redirect(url_for("dashboard"))


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    record = file_for_user(file_id)
    path = os.path.join(STORAGE, record["stored_name"])
    try:
        with connect_db() as con:
            con.execute("DELETE FROM shares WHERE file_id=?", (file_id,))
            con.execute("DELETE FROM files WHERE id=?", (file_id,))
        if os.path.exists(path):
            os.remove(path)
        flash("File and its share links deleted.", "success")
    except Exception:
        app.logger.exception("Delete failed")
        flash("Delete failed. Check the terminal.", "danger")
    return redirect(url_for("dashboard"))


@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def create_share(file_id):
    record = file_for_user(file_id)
    try:
        hours = int(request.form.get("hours", "24"))
    except (ValueError, TypeError):
        hours = 24
    if hours not in (1, 6, 24, 72, 168):
        hours = 24

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expiry = (now() + timedelta(hours=hours)).isoformat()
    with connect_db() as con:
        con.execute(
            "INSERT INTO shares(file_id,token_hash,expires) VALUES(?,?,?)",
            (record["id"], token_hash, expiry)
        )

    return render_template(
        "share_created.html",
        share_url=url_for("public_share", token=token, _external=True),
        filename=record["filename"],
        expiry=expiry
    )


def get_share(token, include_storage=False):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    extra = ", files.stored_name" if include_storage else ""
    with connect_db() as con:
        share = con.execute(f"""
            SELECT shares.*, files.filename {extra}
            FROM shares JOIN files ON files.id=shares.file_id
            WHERE shares.token_hash=?
        """, (token_hash,)).fetchone()

    if not share:
        abort(404)
    expiry = datetime.fromisoformat(share["expires"])
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= now():
        abort(410)
    return share


@app.route("/s/<token>")
def public_share(token):
    share = get_share(token)
    return render_template("public_share.html", share=share, token=token)


@app.route("/s/<token>/download")
def public_download(token):
    share = get_share(token, include_storage=True)
    try:
        with open(os.path.join(STORAGE, share["stored_name"]), "rb") as source:
            data = cipher.decrypt(source.read())
    except (OSError, InvalidToken):
        app.logger.exception("Shared file decryption failed")
        abort(500)
    return send_file(BytesIO(data), as_attachment=True, download_name=share["filename"])


@app.route("/admin")
@admin_required
def admin():
    with connect_db() as con:
        users = con.execute(
            "SELECT id,username,role,active FROM users ORDER BY id"
        ).fetchall()
        total_files = con.execute("SELECT COUNT(*) AS n FROM files").fetchone()["n"]
        total_shares = con.execute("SELECT COUNT(*) AS n FROM shares").fetchone()["n"]
    return render_template("admin.html", users=users, total_files=total_files, total_shares=total_shares)


@app.route("/admin/create-user", methods=["POST"])
@admin_required
def create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    if not valid_username(username) or len(password) < 10 or role not in ("user", "admin"):
        flash("Invalid username, password or role.", "danger")
    else:
        try:
            with connect_db() as con:
                con.execute(
                    "INSERT INTO users(username,password,role,active) VALUES(?,?,?,1)",
                    (username, generate_password_hash(password), role)
                )
            flash("Account created.", "success")
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:user_id>/status", methods=["POST"])
@admin_required
def change_user_status(user_id):
    active = request.form.get("active") == "1"
    if user_id == session["user_id"] and not active:
        flash("You cannot deactivate your own account.", "warning")
    else:
        with connect_db() as con:
            con.execute("UPDATE users SET active=? WHERE id=?", (int(active), user_id))
        flash("User status updated.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/role/<int:user_id>", methods=["POST"])
@admin_required
def change_role(user_id):
    role = request.form.get("role")
    if role not in ("user", "admin"):
        abort(400)
    if user_id == session["user_id"] and role != "admin":
        flash("You cannot remove your own admin role.", "warning")
    else:
        with connect_db() as con:
            con.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        flash("Role updated.", "success")
    return redirect(url_for("admin"))


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="Access denied."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="Page or file not found."), 404


@app.errorhandler(410)
def expired(error):
    return render_template("share_expired.html"), 410


@app.errorhandler(413)
def too_large(error):
    return render_template("error.html", code=413, message="Maximum upload size is 20 MB."), 413


@app.errorhandler(500)
def internal_error(error):
    app.logger.error("Internal server error: %s", error)
    return render_template("error.html", code=500, message="Something went wrong. Check the terminal."), 500


init_db()

if __name__ == "__main__":
    app.run(debug=False)
