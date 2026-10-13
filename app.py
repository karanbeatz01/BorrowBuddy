"""BorrowBuddy Phase 1: account access and a protected dashboard."""

import os
import re
import sqlite3
from functools import wraps

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from db import close_db, get_db, init_db


app = Flask(__name__)

# Flask signs login sessions with this key, so do not store the key in source code.
secret_key = os.environ.get("BORROWBUDDY_SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "Set BORROWBUDDY_SECRET_KEY before starting BorrowBuddy. "
        "See README.md for local setup."
    )

app.config.update(
    SECRET_KEY=secret_key,
    DATABASE=os.environ.get(
        "BORROWBUDDY_DATABASE",
        os.path.join(app.instance_path, "borrowbuddy.sqlite"),
    ),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

os.makedirs(app.instance_path, exist_ok=True)
init_db(app)
app.teardown_appcontext(close_db)


@app.before_request
def load_logged_in_user():
    """Load the signed-in user's public details for this request."""
    user_id = session.get("user_id")
    g.current_user = (
        get_db()
        .execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        .fetchone()
        if user_id is not None
        else None
    )
    if user_id is not None and g.current_user is None:
        session.clear()


def login_required(view):
    """Send visitors without a valid login to the sign-in page."""

    @wraps(view)
    def wrapped_view(**kwargs):
        if g.current_user is None:
            flash("Please log in to view the dashboard.", "error")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def valid_email(email):
    """Apply a simple shape check without relying on an external email service."""
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash(
                "Username must be 3-30 characters using letters, numbers, or underscores.",
                "error",
            )
        elif not valid_email(email) or len(email) > 254:
            flash("Enter a valid email address (up to 254 characters).", "error")
        elif not 8 <= len(password) <= 128:
            flash("Password must be between 8 and 128 characters.", "error")
        elif password != confirm_password:
            flash("The passwords do not match.", "error")
        else:
            database = get_db()
            existing_user = database.execute(
                """
                SELECT username, email FROM users
                WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
                """,
                (username, email),
            ).fetchone()

            if existing_user is not None:
                if existing_user["username"].casefold() == username.casefold():
                    flash("That username is already taken.", "error")
                else:
                    flash("That email address is already registered.", "error")
            else:
                try:
                    database.execute(
                        """
                        INSERT INTO users (username, email, password_hash)
                        VALUES (?, ?, ?)
                        """,
                        (username, email, generate_password_hash(password)),
                    )
                    database.commit()
                except sqlite3.IntegrityError:
                    # The UNIQUE constraints also protect against simultaneous sign-ups.
                    database.rollback()
                    flash("That username or email address is already registered.", "error")
                else:
                    flash("Your account is ready. Please log in.", "success")
                    return redirect(url_for("login"))

        return render_template("register.html"), 400

    return render_template("register.html")


@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            """
            SELECT id, username, password_hash FROM users
            WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
            """,
            (identity, identity),
        ).fetchone()

        # Keep the same message for an unknown account and a wrong password.
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username/email or password.", "error")
            return render_template("login.html"), 401

        session.clear()
        session["user_id"] = user["id"]
        flash("You are now logged in.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=("POST",))
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=g.current_user)


if __name__ == "__main__":
    app.run(debug=False)
