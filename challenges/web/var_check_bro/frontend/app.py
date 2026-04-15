import socket
import ipaddress
from urllib.parse import urlparse

import requests
from flask import Flask, render_template, request

app = Flask(__name__)

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_NAMES = {"localhost", "var-internal", "internal", "metadata"}


def validate_url(url: str):
    if not url or len(url) > 512:
        return False, "URL missing or too long"

    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Scheme '{parsed.scheme}' not allowed. Use http/https."

    host = parsed.hostname
    if not host:
        return False, "No hostname in URL"

    host_lower = host.lower()
    for bad in BLOCKED_NAMES:
        if bad in host_lower:
            return False, f"VAR rejects '{bad}' hostnames"

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return False, f"DNS resolution failed: {exc}"

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False, "Invalid resolved IP"

    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
        return False, f"VAR cannot review private addresses ({ip})"

    return True, ip


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/review", methods=["POST"])
def review():
    url = (request.form.get("video_url") or "").strip()
    ok, info = validate_url(url)
    if not ok:
        return render_template("result.html", error=info, url=url), 400

    try:
        resp = requests.get(
            url,
            timeout=4,
            allow_redirects=False,
            headers={"User-Agent": "VAR-ReviewBot/1.0"},
        )
    except requests.RequestException as exc:
        return render_template("result.html", error=f"Fetch failed: {exc}", url=url), 502

    preview = resp.text[:6000]
    return render_template(
        "result.html",
        url=url,
        resolved_ip=info,
        status=resp.status_code,
        content=preview,
    )


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /review\n", 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
