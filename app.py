"""BorrowBuddy Phase 1: account access and a protected dashboard."""

import os
import re
import sqlite3
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from db import close_db, get_db, init_db


ITEM_CATEGORIES = (
    "Calculators",
    "Books",
    "Lab Equipment",
    "Chargers & Adapters",
    "Other",
)
ITEM_CONDITIONS = ("new", "good", "fair", "worn")


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
CSRFProtect(app)

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
            flash("Please log in to continue.", "error")
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

        return render_template("register.html", username=username, email=email), 400

    return render_template("register.html", username="", email="")


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
    database = get_db()
    my_item_count = database.execute(
        "SELECT COUNT(*) AS count FROM items WHERE owner_id = ?",
        (g.current_user["id"],),
    ).fetchone()["count"]
    available_item_count = database.execute(
        "SELECT COUNT(*) AS count FROM items WHERE status = ?",
        ("available",),
    ).fetchone()["count"]
    return render_template(
        "dashboard.html",
        user=g.current_user,
        my_item_count=my_item_count,
        available_item_count=available_item_count,
    )


def item_form_values():
    """Read and normalize the public item fields submitted by a form."""
    return {
        "name": request.form.get("name", "").strip(),
        "description": request.form.get("description", "").strip(),
        "category": request.form.get("category", "").strip(),
        "item_condition": request.form.get("item_condition", "").strip(),
        "location": request.form.get("location", "").strip(),
    }


def validate_item(values):
    """Reject invalid item data before it reaches the database."""
    if not 1 <= len(values["name"]) <= 100:
        return "Name is required and must be 100 characters or fewer."
    if len(values["description"]) > 1000:
        return "Description must be 1,000 characters or fewer."
    if values["category"] not in ITEM_CATEGORIES:
        return "Choose a category from the list."
    if values["item_condition"] not in ITEM_CONDITIONS:
        return "Choose a valid item condition."
    if not 1 <= len(values["location"]) <= 120:
        return "Location is required and must be 120 characters or fewer."
    return None


def owned_item_or_404(item_id):
    """Only return an item if the signed-in user owns it."""
    item = get_db().execute(
        "SELECT * FROM items WHERE id = ? AND owner_id = ?",
        (item_id, g.current_user["id"]),
    ).fetchone()
    if item is None:
        abort(404)
    return item


def escape_like(value):
    """Make search wildcards literal rather than letting users broaden a search."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@app.route("/browse")
def browse():
    keyword = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "").strip()
    item_condition = request.args.get("condition", "").strip()
    location = request.args.get("location", "").strip()[:120]

    filters = ["items.status = ?"]
    parameters = ["available"]
    if g.current_user is not None:
        filters.append("items.owner_id != ?")
        parameters.append(g.current_user["id"])
    if keyword:
        pattern = f"%{escape_like(keyword)}%"
        filters.append("(items.name LIKE ? ESCAPE '\\' OR items.description LIKE ? ESCAPE '\\')")
        parameters.extend((pattern, pattern))
    if category in ITEM_CATEGORIES:
        filters.append("items.category = ?")
        parameters.append(category)
    else:
        category = ""
    if item_condition in ITEM_CONDITIONS:
        filters.append("items.item_condition = ?")
        parameters.append(item_condition)
    else:
        item_condition = ""
    if location:
        filters.append("items.location LIKE ? ESCAPE '\\'")
        parameters.append(f"%{escape_like(location)}%")

    query = f"""
        SELECT items.*, users.username AS owner_username
        FROM items
        JOIN users ON users.id = items.owner_id
        WHERE {" AND ".join(filters)}
        ORDER BY items.created_at DESC, items.id DESC
    """
    items = get_db().execute(query, parameters).fetchall()
    return render_template(
        "browse.html",
        items=items,
        categories=ITEM_CATEGORIES,
        conditions=ITEM_CONDITIONS,
        filters={
            "q": keyword,
            "category": category,
            "condition": item_condition,
            "location": location,
        },
    )


@app.route("/my-items")
@login_required
def my_items():
    items = get_db().execute(
        """
        SELECT * FROM items
        WHERE owner_id = ?
        ORDER BY created_at DESC, id DESC
        """,
        (g.current_user["id"],),
    ).fetchall()
    return render_template("my_items.html", items=items)


@app.route("/items/new", methods=("GET", "POST"))
@login_required
def add_item():
    if request.method == "POST":
        values = item_form_values()
        error = validate_item(values)
        if error:
            flash(error, "error")
            return render_template(
                "item_form.html",
                title="Add an item",
                button_label="Add item",
                item=values,
                categories=ITEM_CATEGORIES,
                conditions=ITEM_CONDITIONS,
            ), 400

        database = get_db()
        database.execute(
            """
            INSERT INTO items
                (owner_id, name, description, category, item_condition, location)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                g.current_user["id"],
                values["name"],
                values["description"],
                values["category"],
                values["item_condition"],
                values["location"],
            ),
        )
        database.commit()
        flash("Your item has been added.", "success")
        return redirect(url_for("my_items"))

    return render_template(
        "item_form.html",
        title="Add an item",
        button_label="Add item",
        item={},
        categories=ITEM_CATEGORIES,
        conditions=ITEM_CONDITIONS,
    )


@app.route("/items/<int:item_id>")
def item_detail(item_id):
    item = get_db().execute(
        """
        SELECT items.*, users.username AS owner_username
        FROM items
        JOIN users ON users.id = items.owner_id
        WHERE items.id = ?
        """,
        (item_id,),
    ).fetchone()
    if item is None:
        abort(404)
    return render_template("item_detail.html", item=item)


@app.route("/items/<int:item_id>/edit", methods=("GET", "POST"))
@login_required
def edit_item(item_id):
    item = owned_item_or_404(item_id)
    if request.method == "POST":
        values = item_form_values()
        error = validate_item(values)
        if error:
            flash(error, "error")
            values["status"] = item["status"]
            return render_template(
                "item_form.html",
                title="Edit item",
                button_label="Save changes",
                item=values,
                categories=ITEM_CATEGORIES,
                conditions=ITEM_CONDITIONS,
            ), 400

        database = get_db()
        database.execute(
            """
            UPDATE items
            SET name = ?, description = ?, category = ?, item_condition = ?,
                location = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND owner_id = ?
            """,
            (
                values["name"],
                values["description"],
                values["category"],
                values["item_condition"],
                values["location"],
                item_id,
                g.current_user["id"],
            ),
        )
        database.commit()
        flash("Your changes have been saved.", "success")
        return redirect(url_for("my_items"))

    return render_template(
        "item_form.html",
        title="Edit item",
        button_label="Save changes",
        item=dict(item),
        categories=ITEM_CATEGORIES,
        conditions=ITEM_CONDITIONS,
    )


@app.route("/items/<int:item_id>/delete", methods=("POST",))
@login_required
def delete_item(item_id):
    owned_item_or_404(item_id)
    database = get_db()
    database.execute(
        "DELETE FROM items WHERE id = ? AND owner_id = ?",
        (item_id, g.current_user["id"]),
    )
    database.commit()
    flash("Your item has been deleted.", "success")
    return redirect(url_for("my_items"))


@app.route("/items/<int:item_id>/toggle", methods=("POST",))
@login_required
def toggle_item_status(item_id):
    item = owned_item_or_404(item_id)
    if item["status"] not in ("available", "unavailable"):
        flash("Only available and unavailable items can be toggled.", "error")
        return redirect(url_for("my_items"))

    # This action can switch only between these two values, never to "borrowed".
    new_status = "unavailable" if item["status"] == "available" else "available"
    database = get_db()
    database.execute(
        """
        UPDATE items
        SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND owner_id = ?
        """,
        (new_status, item_id, g.current_user["id"]),
    )
    database.commit()
    flash(f"Item is now {new_status}.", "success")
    return redirect(url_for("my_items"))


if __name__ == "__main__":
    app.run(debug=False)
