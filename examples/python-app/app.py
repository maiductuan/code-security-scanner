import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # SQL Injection via string formatting (vulnerable to security/sql-injection)
    cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    user = cursor.fetchone()
    # Reflected XSS (vulnerable to security/xss)
    return "<h1>User: %s</h1>" % user[1]

@app.route("/ping")
def ping():
    ip = request.args.get("ip")
    # Command Injection (vulnerable to security/command-injection)
    os.system("ping -c 1 " + ip)
    return "Pinged!"

if __name__ == "__main__":
    app.run(debug=True)
