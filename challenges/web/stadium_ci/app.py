import os
import secrets

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Static asset extensions that Varnish/edge cache layer serves directly.
# These are allowed to bypass the auth gate for CDN compatibility.
STATIC_EXT = (
    ".css",
    ".js",
    ".svg",
    ".ico",
    ".map",
    ".woff",
    ".woff2",
    ".png",
)

REPORT_ID = os.environ.get("REPORT_ID", "infodays-final-2026")


def load_flag() -> str:
    try:
        with open("/flag.txt", "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "INFODAYS{flag_not_initialized}"


def _is_admin_path(path: str) -> bool:
    return path == "/admin" or path.startswith("/admin/")


@app.before_request
def auth_gate():
    path = request.path
    # CDN passthrough: static assets never require auth, regardless of namespace.
    if path.endswith(STATIC_EXT):
        return None
    # Protect the /admin namespace otherwise.
    if _is_admin_path(path):
        if session.get("role") != "admin":
            return render_template("403.html", path=path), 403
    return None


def _strip_static_suffix(subpath: str) -> str:
    # Legacy Varnish cache support: admin handlers historically served cached
    # variants of themselves under /admin/<name>.<ext>. Normalize the subpath
    # back to its canonical form for dispatch.
    for ext in STATIC_EXT:
        if subpath.endswith(ext):
            return subpath[: -len(ext)]
    return subpath


@app.route("/")
def index():
    return render_template("index.html", role=session.get("role", "guest"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        if username == "scout" and password == "scout":
            session["role"] = "scout"
            return redirect(url_for("public_dashboard"))
        return render_template("login.html", error="Invalid credentials"), 401
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def public_dashboard():
    return render_template("dashboard.html", role=session.get("role", "guest"))


@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Allow: /admin/*.css\n"
        "Allow: /admin/*.js\n"
    )
    return body, 200, {"Content-Type": "text/plain"}


@app.route("/admin", defaults={"subpath": ""})
@app.route("/admin/", defaults={"subpath": ""})
@app.route("/admin/<path:subpath>", methods=["GET", "POST"])
def admin_router(subpath):
    clean = _strip_static_suffix(subpath)

    if clean in ("", "dashboard"):
        return render_template("admin_dashboard.html", report_id=REPORT_ID)

    if clean == f"reports/{REPORT_ID}":
        return render_template(
            "admin_report.html",
            flag=load_flag(),
            report_id=REPORT_ID,
        )

    if clean.startswith("reports/"):
        return render_template(
            "admin_report.html",
            flag="[SEALED — this report is not the final match decision]",
            report_id=clean.split("/", 1)[1],
        )

    abort(404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
