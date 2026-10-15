"""BorrowBuddy Phase 1: account access and a protected dashboard."""

import hmac
import os
import re
import sqlite3
import time
from datetime import date, datetime, timedelta
from functools import wraps
from threading import Lock

import click
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
MAX_REQUEST_DAYS = 30
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 15 * 60
LOGIN_FAILURES = {}
LOGIN_FAILURES_LOCK = Lock()


instance_path = os.path.abspath(
    os.environ.get(
        "BORROWBUDDY_INSTANCE_PATH",
        os.path.join(os.path.dirname(__file__), "instance"),
    )
)
app = Flask(__name__, instance_path=instance_path)

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
    DEBUG=False,
    INVITE_CODE=os.environ.get("BORROWBUDDY_INVITE_CODE"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "BORROWBUDDY_COOKIE_SECURE", ""
    ).strip().lower() in {"1", "true", "yes", "on"},
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
CSRFProtect(app)

os.makedirs(app.instance_path, exist_ok=True)
init_db(app)
app.teardown_appcontext(close_db)


@app.after_request
def add_security_headers(response):
    """Set browser-side protections consistently, including on error responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
        "form-action 'self'; object-src 'none'; script-src 'self'; "
        "style-src 'self'; img-src 'self' data:"
    )
    return response


@app.errorhandler(403)
def forbidden(_error):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(_error):
    # Keep unexpected exception details in the server log, not in the browser.
    return render_template("500.html"), 500


@app.before_request
def load_logged_in_user():
    """Load the signed-in user's public details for this request."""
    user_id = session.get("user_id")
    g.current_user = (
        get_db()
        .execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,))
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


def admin_required(view):
    """Restrict admin pages to a logged-in account with the database role."""

    @wraps(view)
    def wrapped_view(**kwargs):
        if g.current_user is None or not g.current_user["is_admin"]:
            abort(403)
        return view(**kwargs)

    return wrapped_view


@app.cli.command("make-admin")
@click.argument("username")
def make_admin(username):
    """Grant the admin role to an existing account by username."""
    database = get_db()
    cursor = database.execute(
        "UPDATE users SET is_admin = 1 WHERE username = ? COLLATE NOCASE",
        (username.strip(),),
    )
    if cursor.rowcount != 1:
        database.rollback()
        raise click.ClickException(f"No account found for username '{username}'.")
    database.commit()
    click.echo(f"Admin role granted to {username}.")


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
        invite_code = request.form.get("invite_code", "")

        if (
            app.config["INVITE_CODE"] is not None
            and not hmac.compare_digest(invite_code, app.config["INVITE_CODE"])
        ):
            flash("Enter the valid invite code to register.", "error")
        elif not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
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

        return render_template(
            "register.html",
            username=username,
            email=email,
            invite_code_required=app.config["INVITE_CODE"] is not None,
        ), 400

    return render_template(
        "register.html",
        username="",
        email="",
        invite_code_required=app.config["INVITE_CODE"] is not None,
    )


@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        attempt_key = (identity.casefold(), request.remote_addr or "unknown")
        now = time.monotonic()
        # This small in-process sliding window needs no dependency, but resets
        # on restart and is not shared between multiple server workers.
        with LOGIN_FAILURES_LOCK:
            for key, state in list(LOGIN_FAILURES.items()):
                state["failures"] = [
                    failed_at
                    for failed_at in state["failures"]
                    if now - failed_at < LOGIN_WINDOW_SECONDS
                ]
                if (
                    now >= state["locked_until"]
                    and not state["failures"]
                ):
                    LOGIN_FAILURES.pop(key, None)
            attempt = LOGIN_FAILURES.get(attempt_key)
            is_locked_out = attempt is not None and attempt["locked_until"] > now
        if is_locked_out:
            flash("Too many login attempts. Try again later.", "error")
            return render_template("login.html"), 429

        user = get_db().execute(
            """
            SELECT id, username, password_hash FROM users
            WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
            """,
            (identity, identity),
        ).fetchone()

        # Keep the same message for an unknown account and a wrong password.
        if user is None or not check_password_hash(user["password_hash"], password):
            with LOGIN_FAILURES_LOCK:
                failure_time = time.monotonic()
                attempt = LOGIN_FAILURES.get(attempt_key)
                if attempt is not None and attempt["locked_until"] > failure_time:
                    is_locked_out = True
                else:
                    is_locked_out = False
                    if attempt is None:
                        attempt = {"failures": [], "locked_until": 0.0}
                    attempt["failures"] = [
                        failed_at
                        for failed_at in attempt["failures"]
                        if failure_time - failed_at < LOGIN_WINDOW_SECONDS
                    ]
                    attempt["failures"].append(failure_time)
                    if len(attempt["failures"]) >= MAX_LOGIN_ATTEMPTS:
                        attempt["locked_until"] = failure_time + LOGIN_LOCKOUT_SECONDS
                    LOGIN_FAILURES[attempt_key] = attempt
            if is_locked_out:
                flash("Too many login attempts. Try again later.", "error")
                return render_template("login.html"), 429
            flash("Invalid username/email or password.", "error")
            return render_template("login.html"), 401

        with LOGIN_FAILURES_LOCK:
            LOGIN_FAILURES.pop(attempt_key, None)
        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        flash("You are now logged in.", "success")
        # Do not accept a "next" URL from the request: always use a known
        # internal endpoint to prevent external open redirects.
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
    currently_borrowing_count = database.execute(
        """
        SELECT COUNT(*) AS count
        FROM borrow_requests
        WHERE borrower_id = ? AND status = ? AND returned_at IS NULL
        """,
        (g.current_user["id"], "approved"),
    ).fetchone()["count"]
    overdue_lent_count = database.execute(
        f"""
        SELECT COUNT(*) AS count FROM borrow_requests
        WHERE owner_id = ? AND {overdue_condition()}
        """,
        (g.current_user["id"],),
    ).fetchone()["count"]
    overdue_borrowed_count = database.execute(
        f"""
        SELECT COUNT(*) AS count FROM borrow_requests
        WHERE borrower_id = ? AND {overdue_condition()}
        """,
        (g.current_user["id"],),
    ).fetchone()["count"]
    available_item_count = database.execute(
        "SELECT COUNT(*) AS count FROM items WHERE status = ?",
        ("available",),
    ).fetchone()["count"]
    incoming_pending_count = database.execute(
        "SELECT COUNT(*) AS count FROM borrow_requests WHERE owner_id = ? AND status = ?",
        (g.current_user["id"], "pending"),
    ).fetchone()["count"]
    outgoing_pending_count = database.execute(
        "SELECT COUNT(*) AS count FROM borrow_requests WHERE borrower_id = ? AND status = ?",
        (g.current_user["id"], "pending"),
    ).fetchone()["count"]
    lent_out_count = database.execute(
        "SELECT COUNT(*) AS count FROM items WHERE owner_id = ? AND status = ?",
        (g.current_user["id"], "borrowed"),
    ).fetchone()["count"]
    return render_template(
        "dashboard.html",
        user=g.current_user,
        my_item_count=my_item_count,
        available_item_count=available_item_count,
        incoming_pending_count=incoming_pending_count,
        outgoing_pending_count=outgoing_pending_count,
        lent_out_count=lent_out_count,
        currently_borrowing_count=currently_borrowing_count,
        overdue_lent_count=overdue_lent_count,
        overdue_borrowed_count=overdue_borrowed_count,
    )


@app.route("/admin")
@admin_required
def admin_dashboard():
    database = get_db()
    users = database.execute(
        """
        SELECT users.id, users.username, users.created_at,
               COUNT(items.id) AS item_count
        FROM users
        LEFT JOIN items ON items.owner_id = users.id
        GROUP BY users.id, users.username, users.created_at
        ORDER BY users.username COLLATE NOCASE
        """
    ).fetchall()
    return render_template(
        "admin.html",
        users=users,
        total_user_count=len(users),
    )


@app.route("/admin/items")
@admin_required
def admin_items():
    items = get_db().execute(
        """
        SELECT items.id, items.name, items.status, items.category,
               items.location, users.username AS owner_username
        FROM items
        JOIN users ON users.id = items.owner_id
        ORDER BY items.created_at DESC, items.id DESC
        """
    ).fetchall()
    return render_template("admin_items.html", items=items)


@app.route("/admin/items/<int:item_id>/delete", methods=("POST",))
@admin_required
def admin_delete_item(item_id):
    database = get_db()
    try:
        database.execute("BEGIN IMMEDIATE")
        # Recheck the database role while holding the write lock; the template
        # and session are not authority to perform an administrative delete.
        admin = database.execute(
            "SELECT is_admin FROM users WHERE id = ? AND is_admin = 1",
            (g.current_user["id"],),
        ).fetchone()
        if admin is None:
            database.rollback()
            abort(403)

        item = database.execute(
            "SELECT id, name, status FROM items WHERE id = ?",
            (item_id,),
        ).fetchone()
        if item is None:
            database.rollback()
            abort(404)
        if (
            item["status"] == "borrowed"
            and request.form.get("confirm_borrowed_delete") != "yes"
        ):
            database.rollback()
            flash(
                "This item is borrowed. Confirm deletion to permanently remove "
                "its borrow-request and return history.",
                "error",
            )
            return redirect(url_for("admin_items"))

        if item["status"] == "borrowed":
            # Close any active loan before deleting the item. The foreign-key
            # cascade then removes its dependent request history with the item.
            database.execute(
                """
                UPDATE borrow_requests
                SET status = 'returned',
                    returned_at = COALESCE(returned_at, CURRENT_TIMESTAMP),
                    updated_at = CURRENT_TIMESTAMP
                WHERE item_id = ? AND status = 'approved'
                """,
                (item_id,),
            )
            database.execute(
                """
                UPDATE borrow_requests
                SET status = 'rejected', updated_at = CURRENT_TIMESTAMP
                WHERE item_id = ? AND status = 'pending'
                """,
                (item_id,),
            )
            database.execute(
                """
                UPDATE items SET status = 'available', updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND status = 'borrowed'
                """,
                (item_id,),
            )

        deleted = database.execute(
            """
            DELETE FROM items
            WHERE id = ?
              AND (status != 'borrowed' OR ? = 'yes')
              AND EXISTS (
                  SELECT 1 FROM users
                  WHERE id = ? AND is_admin = 1
              )
            """,
            (item_id, request.form.get("confirm_borrowed_delete", ""), g.current_user["id"]),
        )
        if deleted.rowcount != 1:
            database.rollback()
            abort(403)
        database.commit()
    except Exception:
        if database.in_transaction:
            database.rollback()
        raise

    if item["status"] == "borrowed":
        flash(
            "Borrowed item deleted. Its borrow-request and return history was also removed.",
            "success",
        )
    else:
        flash("Item deleted.", "success")
    return redirect(url_for("admin_items"))


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


def parse_proposed_return_date(raw_date):
    """Accept only a real ISO date from tomorrow through 30 days from today."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw_date):
        return None
    try:
        proposed_date = datetime.strptime(raw_date, "%Y-%m-%d").date()
    except ValueError:
        return None
    if proposed_date.isoformat() != raw_date:
        return None
    today = date.today()
    if today < proposed_date <= today + timedelta(days=MAX_REQUEST_DAYS):
        return proposed_date
    return None


def request_item_query(item_id, borrower_id):
    """Find a pending request for one borrower and item, if it exists."""
    return get_db().execute(
        """
        SELECT id, proposed_return_date
        FROM borrow_requests
        WHERE item_id = ? AND borrower_id = ? AND status = ?
        """,
        (item_id, borrower_id, "pending"),
    ).fetchone()


def overdue_condition(table="borrow_requests"):
    """Share the overdue rule so dashboard totals and page badges agree."""
    return (
        f"{table}.status = 'approved' "
        f"AND {table}.due_date < date('now') "
        f"AND {table}.returned_at IS NULL"
    )


def overdue_select_fields(table="borrow_requests"):
    """Compute overdue state and age directly from the database date."""
    condition = overdue_condition(table)
    return f"""
        CASE WHEN {condition} THEN 1 ELSE 0 END AS is_overdue,
        CASE WHEN {condition}
             THEN CAST(julianday(date('now')) - julianday({table}.due_date) AS INTEGER)
             ELSE 0
        END AS days_overdue
    """


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
    parameters = []
    if g.current_user is not None:
        # The LEFT JOIN lets each card show the logged-in user's pending request.
        pending_join = """
            LEFT JOIN borrow_requests pending_request
                ON pending_request.item_id = items.id
                AND pending_request.borrower_id = ?
                AND pending_request.status = 'pending'
        """
        parameters.append(g.current_user["id"])
        filters.append("items.owner_id != ?")
    else:
        pending_join = "LEFT JOIN borrow_requests pending_request ON 0"
    parameters.append("available")
    if g.current_user is not None:
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
        SELECT items.*, users.username AS owner_username,
               pending_request.id AS pending_request_id,
               pending_request.proposed_return_date AS pending_return_date
        FROM items
        JOIN users ON users.id = items.owner_id
        {pending_join}
        WHERE {" AND ".join(filters)}
        ORDER BY items.created_at DESC, items.id DESC
    """
    items = get_db().execute(query, parameters).fetchall()
    today = date.today()
    return render_template(
        "browse.html",
        items=items,
        categories=ITEM_CATEGORIES,
        conditions=ITEM_CONDITIONS,
        minimum_return_date=(today + timedelta(days=1)).isoformat(),
        maximum_return_date=(today + timedelta(days=MAX_REQUEST_DAYS)).isoformat(),
        filters={
            "q": keyword,
            "category": category,
            "condition": item_condition,
            "location": location,
        },
    )


@app.route("/items/<int:item_id>/request", methods=("POST",))
@login_required
def request_item(item_id):
    database = get_db()
    item = database.execute(
        "SELECT id, owner_id, status FROM items WHERE id = ?",
        (item_id,),
    ).fetchone()
    if item is None:
        abort(404)
    if item["owner_id"] == g.current_user["id"]:
        abort(403)
    if item["status"] != "available":
        flash("This item is no longer available to request.", "error")
        return redirect(url_for("item_detail", item_id=item_id))
    raw_date = request.form.get("proposed_return_date", "").strip()
    proposed_date = parse_proposed_return_date(raw_date)
    if proposed_date is None:
        flash("Choose a valid return date from tomorrow through 30 days ahead.", "error")
        return redirect(url_for("item_detail", item_id=item_id))
    if request_item_query(item_id, g.current_user["id"]) is not None:
        flash("You already have a pending request for this item.", "error")
        return redirect(url_for("item_detail", item_id=item_id))

    try:
        # Select owner_id from the item row; the browser never supplies it.
        cursor = database.execute(
            """
            INSERT INTO borrow_requests
                (item_id, borrower_id, owner_id, proposed_return_date, status)
            SELECT id, ?, owner_id, ?, ?
            FROM items
            WHERE id = ? AND status = ? AND owner_id != ?
            """,
            (
                g.current_user["id"],
                proposed_date.isoformat(),
                "pending",
                item_id,
                "available",
                g.current_user["id"],
            ),
        )
        if cursor.rowcount != 1:
            database.rollback()
            flash("This item is no longer available to request.", "error")
            return redirect(url_for("item_detail", item_id=item_id))
        database.commit()
    except sqlite3.IntegrityError:
        database.rollback()
        if request_item_query(item_id, g.current_user["id"]) is not None:
            flash("You already have a pending request for this item.", "error")
            return redirect(url_for("item_detail", item_id=item_id))
        raise

    flash("Your request has been sent to the item owner.", "success")
    return redirect(url_for("my_requests"))


@app.route("/incoming-requests")
@login_required
def incoming_requests():
    requests = get_db().execute(
        f"""
        SELECT borrow_requests.*, items.name AS item_name,
               items.status AS item_status, users.username AS borrower_username,
               {overdue_select_fields()}
        FROM borrow_requests
        JOIN items ON items.id = borrow_requests.item_id
        JOIN users ON users.id = borrow_requests.borrower_id
        WHERE borrow_requests.owner_id = ?
        ORDER BY CASE borrow_requests.status WHEN 'pending' THEN 0 ELSE 1 END,
                 borrow_requests.created_at DESC, borrow_requests.id DESC
        """,
        (g.current_user["id"],),
    ).fetchall()
    active_requests = [row for row in requests if row["status"] != "returned"]
    history_requests = [row for row in requests if row["status"] == "returned"]
    return render_template(
        "incoming_requests.html",
        requests=active_requests,
        history_requests=history_requests,
    )


@app.route("/my-requests")
@login_required
def my_requests():
    requests_made = get_db().execute(
        f"""
        SELECT borrow_requests.*, items.name AS item_name,
               {overdue_select_fields()},
               users.username AS owner_username
        FROM borrow_requests
        JOIN items ON items.id = borrow_requests.item_id
        JOIN users ON users.id = borrow_requests.owner_id
        WHERE borrow_requests.borrower_id = ?
        ORDER BY CASE borrow_requests.status WHEN 'pending' THEN 0 ELSE 1 END,
                 borrow_requests.created_at DESC, borrow_requests.id DESC
        """,
        (g.current_user["id"],),
    ).fetchall()
    active_requests = [row for row in requests_made if row["status"] != "returned"]
    history_requests = [row for row in requests_made if row["status"] == "returned"]
    return render_template(
        "my_requests.html",
        requests=active_requests,
        history_requests=history_requests,
    )


def owned_request_or_404(request_id):
    """Limit incoming request actions to the item's stored owner."""
    borrow_request = get_db().execute(
        "SELECT * FROM borrow_requests WHERE id = ? AND owner_id = ?",
        (request_id, g.current_user["id"]),
    ).fetchone()
    if borrow_request is None:
        abort(404)
    return borrow_request


def borrower_request_or_404(request_id):
    """Limit cancellation to the user who created the request."""
    borrow_request = get_db().execute(
        "SELECT * FROM borrow_requests WHERE id = ? AND borrower_id = ?",
        (request_id, g.current_user["id"]),
    ).fetchone()
    if borrow_request is None:
        abort(404)
    return borrow_request


@app.route("/requests/<int:request_id>/report-return", methods=("POST",))
@login_required
def report_return(request_id):
    """Let only the borrower report an approved loan as ready for confirmation."""
    borrow_request = borrower_request_or_404(request_id)
    if borrow_request["status"] != "approved":
        flash("Only approved requests can have a return reported.", "error")
        return redirect(url_for("my_requests"))
    if borrow_request["return_reported_at"] is not None:
        flash("You have already reported this return.", "error")
        return redirect(url_for("my_requests"))

    database = get_db()
    changed = database.execute(
        """
        UPDATE borrow_requests
        SET return_reported_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND borrower_id = ? AND status = ?
          AND return_reported_at IS NULL
        """,
        (request_id, g.current_user["id"], "approved"),
    )
    if changed.rowcount != 1:
        database.rollback()
        flash("This request changed before the return could be reported.", "error")
    else:
        database.commit()
        flash("Return reported. The item owner must confirm it.", "success")
    return redirect(url_for("my_requests"))


@app.route("/requests/<int:request_id>/confirm-return", methods=("POST",))
@login_required
def confirm_return(request_id):
    """Complete the return only after an owner confirms the borrower's report."""
    database = get_db()
    try:
        # Serialize confirmations so two submissions cannot both complete a loan.
        database.execute("BEGIN IMMEDIATE")
        borrow_request = database.execute(
            """
            SELECT borrow_requests.id, borrow_requests.item_id,
                   borrow_requests.status, borrow_requests.return_reported_at,
                   borrow_requests.owner_id, items.status AS item_status
            FROM borrow_requests
            JOIN items ON items.id = borrow_requests.item_id
            WHERE borrow_requests.id = ?
              AND borrow_requests.owner_id = ?
              AND items.owner_id = ?
            """,
            (request_id, g.current_user["id"], g.current_user["id"]),
        ).fetchone()
        if borrow_request is None:
            database.rollback()
            abort(404)
        if borrow_request["status"] != "approved":
            database.rollback()
            flash("Only approved requests can be confirmed as returned.", "error")
            return redirect(url_for("incoming_requests"))
        if borrow_request["return_reported_at"] is None:
            database.rollback()
            flash("The borrower must report the return before you can confirm it.", "error")
            return redirect(url_for("incoming_requests"))
        if borrow_request["item_status"] != "borrowed":
            database.rollback()
            flash("This item is no longer marked as borrowed; no return was completed.", "error")
            return redirect(url_for("incoming_requests"))

        changed = database.execute(
            """
            UPDATE borrow_requests
            SET status = ?, returned_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND owner_id = ? AND status = ?
              AND return_reported_at IS NOT NULL
            """,
            ("returned", request_id, g.current_user["id"], "approved"),
        )
        if changed.rowcount != 1:
            database.rollback()
            flash("This request changed before the return could be confirmed.", "error")
            return redirect(url_for("incoming_requests"))

        changed = database.execute(
            """
            UPDATE items
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND owner_id = ? AND status = ?
            """,
            ("available", borrow_request["item_id"], g.current_user["id"], "borrowed"),
        )
        if changed.rowcount != 1:
            database.rollback()
            flash("The item changed before the return could be confirmed; no changes were saved.", "error")
            return redirect(url_for("incoming_requests"))

        database.commit()
    except Exception:
        database.rollback()
        raise

    flash("Return confirmed. The item is available again.", "success")
    return redirect(url_for("incoming_requests"))


def finish_pending_request(request_id, new_status, actor):
    """Apply reject/cancel only from pending and only for the authorized actor."""
    borrow_request = (
        owned_request_or_404(request_id)
        if actor == "owner"
        else borrower_request_or_404(request_id)
    )
    if borrow_request["status"] != "pending":
        flash("Only pending requests can be changed.", "error")
        return redirect(url_for("incoming_requests" if actor == "owner" else "my_requests"))

    database = get_db()
    if actor == "owner":
        cursor = database.execute(
            """
            UPDATE borrow_requests
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND owner_id = ? AND status = ?
            """,
            (new_status, request_id, g.current_user["id"], "pending"),
        )
    else:
        cursor = database.execute(
            """
            UPDATE borrow_requests
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND borrower_id = ? AND status = ?
            """,
            (new_status, request_id, g.current_user["id"], "pending"),
        )
    if cursor.rowcount != 1:
        database.rollback()
        flash("This request is no longer pending.", "error")
    else:
        database.commit()
        flash(f"Request {new_status}.", "success")
    return redirect(url_for("incoming_requests" if actor == "owner" else "my_requests"))


@app.route("/requests/<int:request_id>/approve", methods=("POST",))
@login_required
def approve_request(request_id):
    # BEGIN IMMEDIATE serializes approvals so only one can claim an available item.
    database = get_db()
    try:
        database.execute("BEGIN IMMEDIATE")
        borrow_request = database.execute(
            """
            SELECT borrow_requests.id, borrow_requests.item_id,
                   borrow_requests.status, borrow_requests.owner_id,
                   items.status AS item_status
            FROM borrow_requests
            JOIN items ON items.id = borrow_requests.item_id
            WHERE borrow_requests.id = ? AND borrow_requests.owner_id = ?
            """,
            (request_id, g.current_user["id"]),
        ).fetchone()
        if borrow_request is None:
            database.rollback()
            abort(404)
        # Repeat both state checks while holding the write lock; the page may be stale.
        if borrow_request["status"] != "pending":
            database.rollback()
            flash("Only pending requests can be approved.", "error")
            return redirect(url_for("incoming_requests"))
        if borrow_request["item_status"] != "available":
            database.rollback()
            flash("This item is no longer available, so the request cannot be approved.", "error")
            return redirect(url_for("incoming_requests"))

        changed = database.execute(
            """
            UPDATE borrow_requests
            SET status = ?, due_date = proposed_return_date,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND owner_id = ? AND status = ?
            """,
            ("approved", request_id, g.current_user["id"], "pending"),
        )
        if changed.rowcount != 1:
            raise sqlite3.IntegrityError("Request is no longer pending.")

        changed = database.execute(
            """
            UPDATE items
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND owner_id = ? AND status = ?
            """,
            ("borrowed", borrow_request["item_id"], g.current_user["id"], "available"),
        )
        if changed.rowcount != 1:
            raise sqlite3.IntegrityError("Item is no longer available.")

        database.execute(
            """
            UPDATE borrow_requests
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE item_id = ? AND id != ? AND status = ?
            """,
            ("rejected", borrow_request["item_id"], request_id, "pending"),
        )
        database.commit()
    except sqlite3.IntegrityError:
        database.rollback()
        flash("The request or item changed before approval; no changes were saved.", "error")
        return redirect(url_for("incoming_requests"))
    except Exception:
        database.rollback()
        raise

    flash("Request approved. Other pending requests for this item were rejected.", "success")
    return redirect(url_for("incoming_requests"))


@app.route("/requests/<int:request_id>/reject", methods=("POST",))
@login_required
def reject_request(request_id):
    return finish_pending_request(request_id, "rejected", "owner")


@app.route("/requests/<int:request_id>/cancel", methods=("POST",))
@login_required
def cancel_request(request_id):
    return finish_pending_request(request_id, "cancelled", "borrower")


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
    pending_request = (
        request_item_query(item_id, g.current_user["id"])
        if g.current_user is not None
        else None
    )
    today = date.today()
    return render_template(
        "item_detail.html",
        item=item,
        pending_request=pending_request,
        minimum_return_date=(today + timedelta(days=1)).isoformat(),
        maximum_return_date=(today + timedelta(days=MAX_REQUEST_DAYS)).isoformat(),
    )


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
    item = owned_item_or_404(item_id)
    if item["status"] == "borrowed":
        flash("A borrowed item cannot be deleted.", "error")
        return redirect(url_for("my_items"))
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
    if item["status"] == "borrowed":
        flash("A borrowed item’s availability cannot be changed.", "error")
        return redirect(url_for("my_items"))
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
    app.run(port=5001, debug=False)
