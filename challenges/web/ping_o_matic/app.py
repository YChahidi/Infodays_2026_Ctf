from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head><title>Network Utility</title></head>
<body>
    <h2>Enter IP to Ping:</h2>
    <form method="POST">
        <input type="text" name="ip" placeholder="8.8.8.8">
        <input type="submit" value="Ping">
    </form>
    <pre>{{ output }}</pre>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    output = ""
    if request.method == 'POST':
        ip = request.form.get('ip')
        # VULNERABILITY: Directly passing user input into a system shell
        output = os.popen(f"ping -c 1 {ip}").read()
    return render_template_string(HTML, output=output)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
