from flask import Flask, request, render_template_string, send_file
import os

app = Flask(__name__)

# A simple home page with a link
@app.route('/')
def index():
    return """
    <h1>Site Archive Viewer</h1>
    <p>Read our latest news: <a href="/view?file=news.txt">news.txt</a></p>
    """

@app.route('/view')
def view():
    # VULNERABILITY: It takes the 'file' parameter and passes it to send_file
    # without checking if the user is trying to leave the current directory.
    filename = request.args.get('file')
    try:
        return send_file(filename)
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    # Create a dummy news file so the app works normally
    with open("news.txt", "w") as f:
        f.write("Welcome to Infodays! Today we are learning Docker.")
    app.run(host='0.0.0.0', port=5000)
