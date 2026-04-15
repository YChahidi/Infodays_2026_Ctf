import json
import os
from pathlib import Path

import requests
from flask import Flask, Response, abort, jsonify, render_template, request

STATE_DIR = Path("/app/state")
CONTRACTS_DIR = Path("/app/contracts")
ANVIL_RPC = os.environ.get("ANVIL_RPC", "http://127.0.0.1:8545")

app = Flask(__name__)


def _deployed() -> dict:
    path = STATE_DIR / "deployed.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _read_source(name: str) -> str:
    p = CONTRACTS_DIR / name
    if not p.exists():
        return f"// source unavailable: {name}"
    return p.read_text()


@app.route("/")
def index():
    state = _deployed()
    return render_template(
        "index.html",
        betting=state.get("betting", "not-deployed"),
        vault=state.get("vault", "not-deployed"),
        seed_wei=state.get("seedWei", "0"),
    )


@app.route("/source/<name>")
def source(name):
    if name not in ("StadiumBetting.sol", "TrophyVault.sol"):
        abort(404)
    code = _read_source(name)
    return render_template("source.html", name=name, code=code)


@app.route("/abi/<name>")
def abi(name):
    if name not in ("StadiumBetting", "TrophyVault"):
        abort(404)
    # forge build emits artifacts under out/<Contract>.sol/<Contract>.json
    artifact = Path("/app/out") / f"{name}.sol" / f"{name}.json"
    if not artifact.exists():
        return jsonify({"error": "abi not compiled"}), 503
    data = json.loads(artifact.read_text())
    return jsonify({"abi": data.get("abi", [])})


@app.route("/deployed.json")
def deployed():
    return jsonify(_deployed())


@app.route("/rpc", methods=["POST"])
def rpc_proxy():
    """Convenience proxy to the internal anvil instance.

    Players can also hit the anvil port directly (mapped to 8010 in compose).
    """
    try:
        r = requests.post(ANVIL_RPC, json=request.get_json(force=True), timeout=10)
    except requests.RequestException as exc:
        return jsonify({"error": str(exc)}), 502
    return Response(r.content, status=r.status_code, content_type="application/json")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
