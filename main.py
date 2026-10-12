"""
Student Information Portal
Features: Login, Student registration, Student records, Search, Edit, Delete, Dashboard

Run:
    pip install flask
    python main.py
Then open http://127.0.0.1:5000  (default login: admin / admin123)
"""
import sqlite3
from functools import wraps

from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
DATABASE = "students.db"


# ---------------------------------------------------------------- Database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            course TEXT NOT NULL,
            year INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    if not db.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", generate_password_hash("admin123")),
        )
    db.commit()
    db.close()


# -------------------------------------------------------------------- Auth
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# --------------------------------------------------------------- Dashboard
@app.route("/")
@login_required
def dashboard():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM students").fetchone()[0]
    by_course = db.execute(
        "SELECT course, COUNT(*) AS n FROM students GROUP BY course ORDER BY n DESC"
    ).fetchall()
    by_year = db.execute(
        "SELECT year, COUNT(*) AS n FROM students GROUP BY year ORDER BY year"
    ).fetchall()
    recent = db.execute(
        "SELECT * FROM students ORDER BY created_at DESC, id DESC LIMIT 5"
    ).fetchall()
    return render_template(
        "dashboard.html", total=total, by_course=by_course,
        by_year=by_year, recent=recent,
    )


# ------------------------------------------- Registration / Records / Search
def read_student_form():
    return {
        "student_id": request.form["student_id"].strip(),
        "full_name": request.form["full_name"].strip(),
        "email": request.form["email"].strip(),
        "phone": request.form["phone"].strip(),
        "course": request.form["course"].strip(),
        "year": request.form["year"].strip(),
    }


def validate(data):
    if not (data["student_id"] and data["full_name"] and data["course"]):
        return "Student ID, full name and course are required."
    if not data["year"].isdigit() or not 1 <= int(data["year"]) <= 8:
        return "Year must be a number between 1 and 8."
    if data["email"] and "@" not in data["email"]:
        return "Please enter a valid email address."
    return None


@app.route("/register", methods=["GET", "POST"])
@login_required
def register():
    data = {k: "" for k in ("student_id", "full_name", "email", "phone", "course", "year")}
    if request.method == "POST":
        data = read_student_form()
        error = validate(data)
        if error:
            flash(error, "error")
        else:
            try:
                get_db().execute(
                    "INSERT INTO students (student_id, full_name, email, phone, course, year) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (data["student_id"], data["full_name"], data["email"],
                     data["phone"], data["course"], int(data["year"])),
                )
                get_db().commit()
                flash("Student registered successfully.", "success")
                return redirect(url_for("records"))
            except sqlite3.IntegrityError:
                flash("A student with that Student ID already exists.", "error")
    return render_template("form.html", title="Register Student", student=data)


@app.route("/records")
@login_required
def records():
    q = request.args.get("q", "").strip()
    db = get_db()
    if q:
        like = f"%{q}%"
        students = db.execute(
            "SELECT * FROM students WHERE student_id LIKE ? OR full_name LIKE ? "
            "OR email LIKE ? OR course LIKE ? ORDER BY full_name",
            (like, like, like, like),
        ).fetchall()
    else:
        students = db.execute("SELECT * FROM students ORDER BY full_name").fetchall()
    return render_template("records.html", students=students, q=q)


@app.route("/edit/<int:sid>", methods=["GET", "POST"])
@login_required
def edit(sid):
    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id = ?", (sid,)).fetchone()
    if student is None:
        flash("Student not found.", "error")
        return redirect(url_for("records"))
    if request.method == "POST":
        data = read_student_form()
        error = validate(data)
        if error:
            flash(error, "error")
            student = data
        else:
            try:
                db.execute(
                    "UPDATE students SET student_id=?, full_name=?, email=?, phone=?, "
                    "course=?, year=? WHERE id=?",
                    (data["student_id"], data["full_name"], data["email"],
                     data["phone"], data["course"], int(data["year"]), sid),
                )
                db.commit()
                flash("Student updated.", "success")
                return redirect(url_for("records"))
            except sqlite3.IntegrityError:
                flash("That Student ID is already used by another student.", "error")
                student = data
    return render_template("form.html", title="Edit Student", student=student)


@app.route("/delete/<int:sid>", methods=["POST"])
@login_required
def delete(sid):
    db = get_db()
    db.execute("DELETE FROM students WHERE id = ?", (sid,))
    db.commit()
    flash("Student deleted.", "success")
    return redirect(url_for("records"))


# --------------------------------------------------------------- Templates
TEMPLATES = {
    "base.html": """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Student Information Portal</title>
  <style>
    *{box-sizing:border-box}
    body{font-family:system-ui,sans-serif;margin:0;background:#f4f6f9;color:#222}
    nav{background:#1f3a5f;color:#fff;padding:12px 20px;display:flex;gap:16px;align-items:center;flex-wrap:wrap}
    nav a{color:#fff;text-decoration:none}
    nav .brand{font-weight:700;margin-right:auto}
    main{max-width:960px;margin:24px auto;padding:0 16px}
    .card{background:#fff;border-radius:10px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:20px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
    .stat{font-size:2rem;font-weight:700;color:#1f3a5f}
    table{width:100%;border-collapse:collapse}
    th,td{text-align:left;padding:8px;border-bottom:1px solid #e5e8ec;font-size:.95rem}
    .table-wrap{overflow-x:auto}
    label{display:block;margin:12px 0 4px;font-weight:600}
    input{width:100%;padding:9px;border:1px solid #c5cbd3;border-radius:6px;font-size:1rem}
    button,.btn{background:#1f3a5f;color:#fff;border:0;padding:9px 16px;border-radius:6px;cursor:pointer;text-decoration:none;font-size:.95rem;display:inline-block}
    .btn-danger{background:#c0392b}.btn-light{background:#6b7a8f}
    .flash{padding:10px 14px;border-radius:6px;margin-bottom:14px}
    .flash.success{background:#d9f2e1;color:#1c6b36}
    .flash.error{background:#fadbd8;color:#922b21}
    form.inline{display:inline}
    .search{display:flex;gap:8px;margin-bottom:14px}
    .search input{flex:1}
  </style>
</head>
<body>
  <nav>
    <span class="brand">Student Portal</span>
    {% if session.user %}
      <a href="{{ url_for('dashboard') }}">Dashboard</a>
      <a href="{{ url_for('records') }}">Records</a>
      <a href="{{ url_for('register') }}">Register</a>
      <a href="{{ url_for('logout') }}">Logout ({{ session.user }})</a>
    {% endif %}
  </nav>
  <main>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="flash {{ category }}">{{ message }}</div>
      {% endfor %}
    {% endwith %}
    {% block content %}{% endblock %}
  </main>
</body>
</html>
""",
    "login.html": """
{% extends 'base.html' %}
{% block content %}
<div class="card" style="max-width:380px;margin:60px auto">
  <h2>Login</h2>
  <form method="post">
    <label>Username</label><input name="username" required autofocus>
    <label>Password</label><input name="password" type="password" required>
    <br><br><button type="submit">Sign in</button>
  </form>
</div>
{% endblock %}
""",
    "dashboard.html": """
{% extends 'base.html' %}
{% block content %}
<h2>Dashboard</h2>
<div class="grid">
  <div class="card"><div>Total students</div><div class="stat">{{ total }}</div></div>
  <div class="card"><div>Courses</div><div class="stat">{{ by_course|length }}</div></div>
</div>
<div class="grid">
  <div class="card">
    <h3>Students per course</h3>
    {% for r in by_course %}<p>{{ r.course }} &mdash; <b>{{ r.n }}</b></p>
    {% else %}<p>No data yet.</p>{% endfor %}
  </div>
  <div class="card">
    <h3>Students per year</h3>
    {% for r in by_year %}<p>Year {{ r.year }} &mdash; <b>{{ r.n }}</b></p>
    {% else %}<p>No data yet.</p>{% endfor %}
  </div>
</div>
<div class="card">
  <h3>Recently registered</h3>
  <div class="table-wrap"><table>
    <tr><th>ID</th><th>Name</th><th>Course</th><th>Year</th></tr>
    {% for s in recent %}
      <tr><td>{{ s.student_id }}</td><td>{{ s.full_name }}</td><td>{{ s.course }}</td><td>{{ s.year }}</td></tr>
    {% else %}<tr><td colspan="4">No students registered yet.</td></tr>{% endfor %}
  </table></div>
</div>
{% endblock %}
""",
    "form.html": """
{% extends 'base.html' %}
{% block content %}
<div class="card">
  <h2>{{ title }}</h2>
  <form method="post">
    <label>Student ID</label><input name="student_id" value="{{ student.student_id }}" required>
    <label>Full name</label><input name="full_name" value="{{ student.full_name }}" required>
    <label>Email</label><input name="email" type="email" value="{{ student.email or '' }}">
    <label>Phone</label><input name="phone" value="{{ student.phone or '' }}">
    <label>Course</label><input name="course" value="{{ student.course }}" required>
    <label>Year</label><input name="year" type="number" min="1" max="8" value="{{ student.year }}" required>
    <br><br>
    <button type="submit">Save</button>
    <a class="btn btn-light" href="{{ url_for('records') }}">Cancel</a>
  </form>
</div>
{% endblock %}
""",
    "records.html": """
{% extends 'base.html' %}
{% block content %}
<div class="card">
  <h2>Student Records</h2>
  <form class="search" method="get">
    <input name="q" value="{{ q }}" placeholder="Search by ID, name, email or course">
    <button type="submit">Search</button>
    {% if q %}<a class="btn btn-light" href="{{ url_for('records') }}">Clear</a>{% endif %}
  </form>
  <div class="table-wrap"><table>
    <tr><th>ID</th><th>Name</th><th>Email</th><th>Course</th><th>Year</th><th>Actions</th></tr>
    {% for s in students %}
    <tr>
      <td>{{ s.student_id }}</td><td>{{ s.full_name }}</td><td>{{ s.email }}</td>
      <td>{{ s.course }}</td><td>{{ s.year }}</td>
      <td>
        <a class="btn" href="{{ url_for('edit', sid=s.id) }}">Edit</a>
        <form class="inline" method="post" action="{{ url_for('delete', sid=s.id) }}"
              onsubmit="return confirm('Delete this student?');">
          <button class="btn-danger" type="submit">Delete</button>
        </form>
      </td>
    </tr>
    {% else %}<tr><td colspan="6">No students found.</td></tr>{% endfor %}
  </table></div>
</div>
{% endblock %}
""",
}
app.jinja_loader = DictLoader(TEMPLATES)


if __name__ == "__main__":
    init_db()
    app.run(debug=True,port=50007)
