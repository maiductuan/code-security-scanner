import subprocess
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # Safe: using parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    # Safe: using render_template_string which auto-escapes html
    return render_template_string("<h1>User: {{ name }}</h1>", name=user[1])

@app.route("/ping")
def ping():
    ip = request.args.get("ip")
    # Safe: using subprocess.run with arguments array (no shell=True)
    if ip and all(c.isalnum() or c in ".-" for c in ip):
        subprocess.run(["ping", "-c", "1", ip], capture_output=True)
        return "Pinged!"
    return "Invalid IP", 400

if __name__ == "__main__":
    app.run(debug=False)
