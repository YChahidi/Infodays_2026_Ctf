import json
import os
from pathlib import Path

import requests
from flask import Flask, Response, abort, jsonify, render_template, request
from web3 import Web3

STATE_DIR = Path("/app/state")
CONTRACTS_DIR = Path("/app/contracts")
ANVIL_RPC = os.environ.get("ANVIL_RPC", "http://127.0.0.1:8545")
FLAG = os.environ.get("FLAG", "INFODAYS{placeholder_flag}")

app = Flask(__name__)
w3 = Web3(Web3.HTTPProvider(ANVIL_RPC))


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


def _load_kernel_abi():
    artifact = Path("/app/out/GoldenBootKernel.sol/GoldenBootKernel.json")
    if not artifact.exists():
        return []
    return json.loads(artifact.read_text()).get("abi", [])


def _golden_boot_event_sig():
    return Web3.keccak(text="GoldenBootClaimed(address)").hex()


@app.route("/")
def index():
    state = _deployed()
    promos = state.get("promos", [])
    return render_template(
        "index.html",
        proxy=state.get("proxy", "not-deployed"),
        impl=state.get("impl", "not-deployed"),
        signer=state.get("signer", "not-deployed"),
        promo1=promos[0] if len(promos) > 0 else "not-deployed",
        promo2=promos[1] if len(promos) > 1 else "not-deployed",
    )


@app.route("/source/<name>")
def source(name):
    if name not in ("GoldenBootKernel.sol",):
        abort(404)
    return render_template("source.html", name=name, code=_read_source(name))


@app.route("/abi/<name>")
def abi(name):
    if name not in ("GoldenBootKernel",):
        abort(404)
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
    try:
        r = requests.post(ANVIL_RPC, json=request.get_json(force=True), timeout=10)
    except requests.RequestException as exc:
        return jsonify({"error": str(exc)}), 502
    return Response(r.content, status=r.status_code, content_type="application/json")


@app.route("/claim", methods=["GET"])
def claim():
    """Return the flag iff a GoldenBootClaimed event has ever been emitted
    from the proxy address.  Players arrange this by upgrading the kernel
    to a malicious implementation that emits the event."""
    state = _deployed()
    proxy = state.get("proxy")
    if not proxy:
        return jsonify({"error": "not deployed"}), 503

    topic = "0x" + _golden_boot_event_sig().lstrip("0x")
    try:
        logs = w3.eth.get_logs({
            "fromBlock": 0,
            "toBlock": "latest",
            "address": Web3.to_checksum_address(proxy),
            "topics": [topic],
        })
    except Exception as exc:
        return jsonify({"error": f"rpc error: {exc!r}"}), 502

    if not logs:
        return jsonify({"status": "unclaimed", "hint": "emit GoldenBootClaimed(address) from the proxy"}), 200

    return jsonify({
        "status": "claimed",
        "flag": FLAG,
        "events": [
            {
                "block": log["blockNumber"],
                "tx":    log["transactionHash"].hex(),
                "topic_winner": "0x" + log["topics"][1].hex()[-40:],
            }
            for log in logs
        ],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
