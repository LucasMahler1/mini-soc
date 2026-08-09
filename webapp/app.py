from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"

DB_PATH = "webapp/bank.db"
UPLOAD_FOLDER = "webapp/uploads"


def init_db():
    """Initialize the database with sample users."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            balance REAL DEFAULT 1000.00
        )
    """)
    # Insert sample users if table is empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, balance) VALUES ('admin', 'admin123', 99999.99)")
        cursor.execute("INSERT INTO users (username, password, balance) VALUES ('lucas', 'password123', 1500.00)")
        cursor.execute("INSERT INTO users (username, password, balance) VALUES ('alice', 'alice456', 2500.00)")
        conn.commit()
    conn.close()


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # INTENTIONALLY VULNERABLE — SQL injection possible
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            cursor.execute(query)
            user = cursor.fetchone()
        except Exception as e:
            user = None
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect(url_for("profile", id=user[0]))
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/profile")
def profile():
    # INTENTIONALLY VULNERABLE — IDOR possible
    user_id = request.args.get("id", 1)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()
    return render_template("profile.html", user=user)


@app.route("/search", methods=["GET", "POST"])
def search():
    results = []
    query = ""
    if request.method == "POST":
        # INTENTIONALLY VULNERABLE — XSS and SQLi possible
        query = request.form.get("query", "")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(f"SELECT * FROM users WHERE username LIKE '%{query}%'")
            results = cursor.fetchall()
        except Exception:
            results = []
        conn.close()

    return render_template("search.html", results=results, query=query)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    message = None
    if request.method == "POST":
        # INTENTIONALLY VULNERABLE — no file type validation
        file = request.files.get("file")
        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            message = f"File uploaded successfully: {file.filename}"

    return render_template("upload.html", message=message)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5001)