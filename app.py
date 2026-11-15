import os
import sqlite3
from functools import wraps
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, g
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "zero_trust.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-demo-secret-key")
app.config["DATABASE"] = DATABASE

# Packet Tracer client IP -> application role. These are demonstration mappings.
NETWORK_ROLES = {
    "192.168.10.10": "Admin",
    "192.168.20.10": "Employee",
    "192.168.30.10": "Student",
    "192.168.50.10": "Guest",
    "192.168.60.10": "IT",
    "192.168.61.10": "HR",
    "192.168.62.10": "Finance",
    "192.168.63.10": "Sales",
    "192.168.64.10": "Marketing",
    "192.168.65.10": "Operations",
}

DEPARTMENTS = [
    "Administration", "Employee", "Student", "Guest",
    "IT", "HR", "Finance", "Sales", "Marketing", "Operations"
]
ROLES = ["Admin", "Employee", "Student", "Guest", "IT", "HR",
         "Finance", "Sales", "Marketing", "Operations"]

ROLE_PERMISSIONS = {
    "Admin": ["View all users", "Create and manage users", "Edit user roles and departments",
              "View security status and audit activity", "View and edit own profile"],
    "Employee": ["View own profile", "Update own contact information"],
    "Student": ["View own profile", "Update own contact information"],
    "Guest": ["View own profile (read-only)"],
    "IT": ["View own profile", "Update own contact information", "Access IT department resources"],
    "HR": ["View own profile", "Update own contact information", "Access HR department resources"],
    "Finance": ["View own profile", "Update own contact information", "Access Finance department resources"],
    "Sales": ["View own profile", "Update own contact information", "Access Sales department resources"],
    "Marketing": ["View own profile", "Update own contact information", "Access Marketing department resources"],
    "Operations": ["View own profile", "Update own contact information", "Access Operations department resources"],
}

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            department TEXT NOT NULL,
            phone TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    seed_users = [
        ("admin", "admin123", "System Administrator", "admin@example.com", "Administration", "9000000001", "Admin"),
        ("employee", "employee123", "Rahul Sharma", "employee@example.com", "Employee", "9000000002", "Employee"),
        ("student", "student123", "Priya Singh", "student@example.com", "Student", "9000000003", "Student"),
        ("guest", "guest123", "Guest User", "guest@example.com", "Guest", "9000000004", "Guest"),
        ("it_user", "it123", "IT User", "it@example.com", "IT", "9000000005", "IT"),
        ("hr_user", "hr123", "HR User", "hr@example.com", "HR", "9000000006", "HR"),
        ("finance_user", "finance123", "Finance User", "finance@example.com", "Finance", "9000000007", "Finance"),
        ("sales_user", "sales123", "Sales User", "sales@example.com", "Sales", "9000000008", "Sales"),
        ("marketing_user", "marketing123", "Marketing User", "marketing@example.com", "Marketing", "9000000009", "Marketing"),
        ("operations_user", "operations123", "Operations User", "operations@example.com", "Operations", "9000000010", "Operations"),

        # Additional demo accounts: three users in total for every role.
        ("admin2", "admin2345", "Ayesha Khan", "admin2@example.com", "Administration", "9000000011", "Admin"),
        ("admin3", "admin3456", "Vikram Rao", "admin3@example.com", "Administration", "9000000012", "Admin"),

        ("employee2", "employee2345", "Arjun Mehta", "employee2@example.com", "Employee", "9000000013", "Employee"),
        ("employee3", "employee3456", "Sneha Reddy", "employee3@example.com", "Employee", "9000000014", "Employee"),

        ("student2", "student2345", "Kavya Nair", "student2@example.com", "Student", "9000000015", "Student"),
        ("student3", "student3456", "Rohan Das", "student3@example.com", "Student", "9000000016", "Student"),

        ("guest2", "guest2345", "Guest Two", "guest2@example.com", "Guest", "9000000017", "Guest"),
        ("guest3", "guest3456", "Guest Three", "guest3@example.com", "Guest", "9000000018", "Guest"),

        ("it_user2", "ituser2345", "Kiran Kumar", "it2@example.com", "IT", "9000000019", "IT"),
        ("it_user3", "ituser3456", "Divya Menon", "it3@example.com", "IT", "9000000020", "IT"),

        ("hr_user2", "hruser2345", "Meera Iyer", "hr2@example.com", "HR", "9000000021", "HR"),
        ("hr_user3", "hruser3456", "Nikhil Jain", "hr3@example.com", "HR", "9000000022", "HR"),

        ("finance_user2", "finance2345", "Ananya Bose", "finance2@example.com", "Finance", "9000000023", "Finance"),
        ("finance_user3", "finance3456", "Rahul Verma", "finance3@example.com", "Finance", "9000000024", "Finance"),

        ("sales_user2", "salesuser2345", "Ishaan Patel", "sales2@example.com", "Sales", "9000000025", "Sales"),
        ("sales_user3", "salesuser3456", "Pooja Shah", "sales3@example.com", "Sales", "9000000026", "Sales"),

        ("marketing_user2", "market2345", "Diya Kapoor", "marketing2@example.com", "Marketing", "9000000027", "Marketing"),
        ("marketing_user3", "market3456", "Aditya Sen", "marketing3@example.com", "Marketing", "9000000028", "Marketing"),

        ("operations_user2", "opsuser2345", "Sanjay Rao", "operations2@example.com", "Operations", "9000000029", "Operations"),
        ("operations_user3", "opsuser3456", "Neha Pillai", "operations3@example.com", "Operations", "9000000030", "Operations"),
    ]

    # Expand to exactly 3 Admin accounts + 60 non-admin accounts.
    # Existing seed accounts use suffixes 1-3; add suffixes 4 onward.
    extra_user_targets = {
        "Employee": 7,
        "Student": 7,
        "Guest": 6,
        "IT": 7,
        "HR": 7,
        "Finance": 7,
        "Sales": 7,
        "Marketing": 6,
        "Operations": 6,
    }
    username_prefixes = {
        "Employee": "employee",
        "Student": "student",
        "Guest": "guest",
        "IT": "it_user",
        "HR": "hr_user",
        "Finance": "finance_user",
        "Sales": "sales_user",
        "Marketing": "marketing_user",
        "Operations": "operations_user",
    }
    password_prefixes = {
        "Employee": "employee",
        "Student": "student",
        "Guest": "guest",
        "IT": "ituser",
        "HR": "hruser",
        "Finance": "finance",
        "Sales": "salesuser",
        "Marketing": "market",
        "Operations": "opsuser",
    }
    for role, target_count in extra_user_targets.items():
        dept = role
        for index in range(4, target_count + 1):
            username = f"{username_prefixes[role]}{index}"
            password = f"{password_prefixes[role]}{index}demo"
            name = f"{role} Member {index}"
            email = f"{username}@example.com"
            phone = str(9000000030 + len(seed_users) - 30 + index)
            seed_users.append((username, password, name, email, dept, phone, role))

    for username, password, name, email, dept, phone, role in seed_users:
        db.execute("""
            INSERT OR IGNORE INTO users
            (username,password_hash,name,email,department,phone,role,active,created_at)
            VALUES (?,?,?,?,?,?,?,1,?)
        """, (username, generate_password_hash(password), name, email, dept, phone, role, datetime.now().isoformat(timespec="seconds")))
    db.commit()
    db.close()

def client_ip():
    # Do not trust X-Forwarded-For unless the app is behind a configured trusted proxy.
    return request.remote_addr or "unknown"

def audit(action, details=""):
    if "username" in session:
        db = get_db()
        db.execute(
            "INSERT INTO audit_logs(username,action,details,client_ip,created_at) VALUES(?,?,?,?,?)",
            (session["username"], action, details, client_ip(), datetime.now().isoformat(timespec="seconds"))
        )
        db.commit()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "Admin":
            audit("ACCESS_DENIED", request.path)
            abort(403)
        return view(*args, **kwargs)
    return wrapped

@app.context_processor
def inject_globals():
    return {"current_year": datetime.now().year}

@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        audit("LOGIN_FAILED", f"Username attempted: {username}")
        flash("Invalid username or password.", "error")
        return redirect(url_for("home"))

    ip = client_ip()
    network_role = NETWORK_ROLES.get(ip)
    # Localhost is used for development demos. On a Packet Tracer-connected
    # deployment, the source IP must map to the same role as the account.
    if ip not in ("127.0.0.1", "::1") and network_role != user["role"]:
        audit("NETWORK_ROLE_MISMATCH", f"Network role={network_role}; account role={user['role']}")
        flash(f"Access denied: network role ({network_role or 'Unmapped'}) does not match account role ({user['role']}).", "error")
        return redirect(url_for("home"))

    session.clear()
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["client_ip"] = ip
    audit("LOGIN_SUCCESS", f"Role={user['role']}")
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (session["username"],)).fetchone()
    total_users = db.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0] if session["role"] == "Admin" else None
    dept_counts = db.execute("SELECT department, COUNT(*) AS total FROM users WHERE active=1 GROUP BY department ORDER BY department").fetchall() if session["role"] == "Admin" else []
    return render_template("dashboard.html", user=user, permissions=ROLE_PERMISSIONS.get(session["role"], []),
                           total_users=total_users, dept_counts=dept_counts, network_ip=session.get("client_ip"))

@app.route("/profile")
@login_required
def profile():
    user = get_db().execute("SELECT * FROM users WHERE username=?", (session["username"],)).fetchone()
    return render_template("profile.html", user=user, can_edit=session["role"] != "Guest")

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if session["role"] == "Guest":
        audit("ACCESS_DENIED", "Guest attempted profile edit")
        abort(403)
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (session["username"],)).fetchone()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        if not name or not email:
            flash("Name and email are required.", "error")
            return render_template("profile_edit.html", user=user)
        # Users cannot change their own role, username or department.
        db.execute("UPDATE users SET name=?, email=?, phone=? WHERE username=?",
                   (name, email, phone, session["username"]))
        db.commit()
        audit("PROFILE_UPDATED", "Updated own contact details")
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))
    return render_template("profile_edit.html", user=user)

@app.route("/admin/users")
@admin_required
def manage_users():
    db = get_db()
    users = db.execute("SELECT username,name,email,department,phone,role,active,created_at FROM users ORDER BY department,username").fetchall()
    return render_template("admin_users.html", users=users)

@app.route("/admin/users/create", methods=["GET", "POST"])
@admin_required
def create_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        role = request.form.get("role", "")
        department = request.form.get("department", "")
        if not all([username, password, name, email]) or role not in ROLES or department not in DEPARTMENTS:
            flash("Complete all required fields and select a valid role and department.", "error")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        else:
            db = get_db()
            try:
                db.execute("""INSERT INTO users(username,password_hash,name,email,department,phone,role,active,created_at)
                              VALUES(?,?,?,?,?,?,?,1,?)""",
                           (username, generate_password_hash(password), name, email, department, phone, role, datetime.now().isoformat(timespec="seconds")))
                db.commit()
                audit("USER_CREATED", f"Created {username} with role {role}")
                flash(f"User '{username}' created.", "success")
                return redirect(url_for("manage_users"))
            except sqlite3.IntegrityError:
                flash("That username already exists.", "error")
    return render_template("user_form.html", user=None, roles=ROLES, departments=DEPARTMENTS, page_title="Create User")

@app.route("/admin/users/<username>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_user(username):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        abort(404)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        role = request.form.get("role", "")
        department = request.form.get("department", "")
        active = 1 if request.form.get("active") == "1" else 0
        if not name or not email or role not in ROLES or department not in DEPARTMENTS:
            flash("Enter valid details.", "error")
        elif username == session["username"] and (role != "Admin" or active == 0):
            flash("You cannot remove your own Admin access or deactivate your account.", "error")
        else:
            db.execute("""UPDATE users SET name=?,email=?,phone=?,role=?,department=?,active=? WHERE username=?""",
                       (name,email,phone,role,department,active,username))
            db.commit()
            audit("USER_UPDATED", f"Updated {username}; role={role}, department={department}, active={active}")
            flash("User updated.", "success")
            return redirect(url_for("manage_users"))
    return render_template("user_form.html", user=user, roles=ROLES, departments=DEPARTMENTS, page_title=f"Edit {username}")

@app.route("/admin/users/<username>/delete", methods=["POST"])
@admin_required
def delete_user(username):
    if username == session["username"]:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("manage_users"))
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        abort(404)
    db.execute("DELETE FROM users WHERE username=?", (username,))
    db.commit()
    audit("USER_DELETED", f"Deleted {username}")
    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("manage_users"))

@app.route("/security-status")
@login_required
def security_status():
    db = get_db()
    logs = db.execute("SELECT username,action,details,client_ip,created_at FROM audit_logs ORDER BY id DESC LIMIT 30").fetchall() if session["role"] == "Admin" else []
    return render_template("security_status.html", network_roles=NETWORK_ROLES, logs=logs, role=session["role"],
                           client_ip=session.get("client_ip"))

@app.route("/admin")
@admin_required
def admin_page():
    db = get_db()
    counts = db.execute("SELECT department,COUNT(*) AS total FROM users WHERE active=1 GROUP BY department ORDER BY department").fetchall()
    return render_template("admin.html", counts=counts)

def role_page_view(required_role):
    """Protect role-specific URLs; mismatched authenticated roles receive HTTP 403."""
    @login_required
    def view():
        current_role = session.get("role")
        # Admin has full application access. Other users may open only their own role URL.
        if current_role not in ("Admin", required_role):
            audit("ACCESS_DENIED", f"Attempted role page: /{required_role.lower()}")
            abort(403)
        return redirect(url_for("dashboard"))
    return view

# Explicit role URLs ensure known-but-unauthorized pages return 403, not 404.
# Unknown URLs continue to use the normal 404 handler.
for _role in ("Employee", "Student", "Guest", "IT", "HR", "Finance",
              "Sales", "Marketing", "Operations"):
    app.add_url_rule(
        f"/{_role.lower()}",
        endpoint=f"{_role.lower()}_role_page",
        view_func=role_page_view(_role),
        methods=["GET"],
    )

@app.route("/logout")
@login_required
def logout():
    audit("LOGOUT", "User logged out")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))

@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="Your role does not have permission to access this resource."), 403

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The requested page was not found."), 404

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
