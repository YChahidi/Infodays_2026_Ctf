from flask import Flask, request, render_template_string

app = Flask(__name__)

INDEX = """
<!doctype html>
<title>VAR Internal Console</title>
<h1>Video Assistant Referee — Internal Console</h1>
<p>Restricted service. Loopback only.</p>
<ul>
    <li><code>GET /</code> — this page</li>
    <li><code>GET /version</code> — build info</li>
    <li><code>GET /review?play=&lt;tag&gt;</code> — render a referee decision tag</li>
</ul>
<p><em>Note:</em> the <code>play</code> field is rendered as a referee decision card template.</p>
"""


@app.route("/")
def index():
    return INDEX


@app.route("/version")
def version():
    return {
        "service": "var-internal",
        "version": "1.3.7",
        "referee": "Pierluigi Collina (simulated)",
        "notes": "DO NOT expose externally — loopback only",
    }


@app.route("/review")
def review():
    play = request.args.get("play", "GOAL")
    # Referees render the decision tag directly into the card template.
    card = (
        "<h2>Referee Decision Card</h2>"
        "<p>Play under review: " + play + "</p>"
        "<p>Signed: VAR Room</p>"
    )
    return render_template_string(card)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5555)
