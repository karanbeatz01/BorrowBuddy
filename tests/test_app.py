"""Phase 3 and 4 regression tests using only disposable project-local databases."""

import os
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTANCE_PATH = PROJECT_ROOT / "instance"
INSTANCE_PATH.mkdir(exist_ok=True)
BOOTSTRAP_DATABASE = INSTANCE_PATH / f".borrowbuddy-test-bootstrap-{os.getpid()}.sqlite"

# app.py initializes its module-level app when imported. Point that startup at a
# throwaway project-local file so test discovery can never touch a user's DB.
os.environ["BORROWBUDDY_INSTANCE_PATH"] = str(INSTANCE_PATH)
os.environ["BORROWBUDDY_DATABASE"] = str(BOOTSTRAP_DATABASE)
os.environ["BORROWBUDDY_SECRET_KEY"] = "test-only-secret-key"
os.environ["BORROWBUDDY_COOKIE_SECURE"] = "false"

from app import LOGIN_FAILURES, app  # noqa: E402
from db import get_db, init_db  # noqa: E402
from flask import abort  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402


PASSWORD = "test-password-123"
CSRF_PATTERN = re.compile(rb'name="csrf_token" value="([^"]+)"')
INITIAL_DATABASE_CONFIG = app.config["DATABASE"]
INITIAL_SECRET_KEY_CONFIG = app.config["SECRET_KEY"]


def remove_sqlite_files(path):
    for suffix in ("", "-journal", "-shm", "-wal"):
        candidate = Path(f"{path}{suffix}")
        if candidate.exists():
            candidate.unlink()


def raise_server_error():
    abort(500)


if "_phase5_test_error" not in app.view_functions:
    app.add_url_rule(
        "/__phase5_test_error",
        endpoint="_phase5_test_error",
        view_func=raise_server_error,
    )


class BorrowBuddySecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database_file = tempfile.NamedTemporaryFile(
            prefix=".borrowbuddy-tests-", suffix=".sqlite", dir=INSTANCE_PATH, delete=False
        )
        cls.database_path = cls.database_file.name
        cls.database_file.close()
        app.config.update(
            DATABASE=cls.database_path,
            TESTING=True,
            DEBUG=False,
            SESSION_COOKIE_SECURE=False,
        )
        init_db(app)
        remove_sqlite_files(BOOTSTRAP_DATABASE)

    @classmethod
    def tearDownClass(cls):
        remove_sqlite_files(cls.database_path)
        remove_sqlite_files(BOOTSTRAP_DATABASE)

    def setUp(self):
        LOGIN_FAILURES.clear()
        with app.app_context():
            database = get_db()
            database.execute("DELETE FROM borrow_requests")
            database.execute("DELETE FROM items")
            database.execute("DELETE FROM users")
            for username in ("owner", "borrower_b", "borrower_c"):
                database.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (
                        username,
                        f"{username}@example.test",
                        generate_password_hash(PASSWORD),
                    ),
                )
            self.owner_id = database.execute(
                "SELECT id FROM users WHERE username = ?", ("owner",)
            ).fetchone()["id"]
            self.borrower_b_id = database.execute(
                "SELECT id FROM users WHERE username = ?", ("borrower_b",)
            ).fetchone()["id"]
            self.borrower_c_id = database.execute(
                "SELECT id FROM users WHERE username = ?", ("borrower_c",)
            ).fetchone()["id"]
            database.execute(
                """
                INSERT INTO items (owner_id, name, description, category, location)
                VALUES (?, ?, ?, ?, ?)
                """,
                (self.owner_id, "Test calculator", "For regression tests", "Calculators", "Library"),
            )
            self.item_id = database.execute(
                "SELECT id FROM items WHERE name = ?", ("Test calculator",)
            ).fetchone()["id"]
            database.commit()

    def get_db_row(self, query, parameters=()):
        with app.app_context():
            return get_db().execute(query, parameters).fetchone()

    def add_request(self, borrower_id, *, status="pending", item_id=None, returned=False):
        target_item_id = item_id or self.item_id
        with app.app_context():
            database = get_db()
            cursor = database.execute(
                """
                INSERT INTO borrow_requests
                    (item_id, borrower_id, owner_id, proposed_return_date, due_date,
                     return_reported_at, returned_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target_item_id,
                    borrower_id,
                    self.owner_id,
                    (date.today() + timedelta(days=5)).isoformat(),
                    (date.today() + timedelta(days=5)).isoformat() if status == "approved" else None,
                    "2026-10-01 12:00:00" if returned else None,
                    "2026-10-02 12:00:00" if returned else None,
                    status,
                ),
            )
            if status == "approved":
                database.execute(
                    "UPDATE items SET status = 'borrowed' WHERE id = ?", (target_item_id,)
                )
            database.commit()
            return cursor.lastrowid

    def grant_admin(self, username="owner"):
        with app.app_context():
            database = get_db()
            database.execute(
                "UPDATE users SET is_admin = 1 WHERE username = ? COLLATE NOCASE",
                (username,),
            )
            database.commit()

    def csrf_token(self, client, path="/dashboard"):
        response = client.get(path)
        match = CSRF_PATTERN.search(response.data)
        self.assertIsNotNone(match, f"Could not find CSRF token in {path}")
        return match.group(1).decode()

    def login(self, username, *, client=None, next_url=None):
        client = client or app.test_client()
        path = "/login"
        if next_url:
            path += f"?next={next_url}"
        csrf_token = self.csrf_token(client, path)
        response = client.post(
            "/login",
            data={
                "identity": username,
                "password": PASSWORD,
                "csrf_token": csrf_token,
            },
        )
        self.assertEqual(response.status_code, 302)
        return client, response

    def make_request(self, client, item_id=None, return_date=None):
        item_id = item_id or self.item_id
        return_date = return_date or (date.today() + timedelta(days=2)).isoformat()
        csrf_token = self.csrf_token(client, f"/items/{item_id}")
        return client.post(
            f"/items/{item_id}/request",
            data={"csrf_token": csrf_token, "proposed_return_date": return_date},
        )

    def authorized_post(self, client, path, data=None):
        payload = dict(data or {})
        payload["csrf_token"] = self.csrf_token(client)
        return client.post(path, data=payload)

    def test_approval_race_only_approves_one_request(self):
        request_b = self.add_request(self.borrower_b_id)
        request_c = self.add_request(self.borrower_c_id)
        owner_client_one, _ = self.login("owner")
        owner_client_two, _ = self.login("owner")
        start_together = Barrier(2)

        def approve_at_once(arguments):
            client, request_id = arguments
            csrf_token = self.csrf_token(client)
            start_together.wait()
            return client.post(
                f"/requests/{request_id}/approve",
                data={"csrf_token": csrf_token},
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(
                executor.map(
                    approve_at_once,
                    [(owner_client_one, request_b), (owner_client_two, request_c)],
                )
            )

        self.assertEqual([response.status_code for response in outcomes], [302, 302])
        rows = self.get_db_row(
            """
            SELECT SUM(status = 'approved') AS approved,
                   SUM(status = 'rejected') AS rejected
            FROM borrow_requests WHERE item_id = ?
            """,
            (self.item_id,),
        )
        self.assertEqual((rows["approved"], rows["rejected"]), (1, 1))
        item = self.get_db_row("SELECT status FROM items WHERE id = ?", (self.item_id,))
        self.assertEqual(item["status"], "borrowed")

    def test_duplicate_pending_request_is_rejected_by_route_and_index(self):
        borrower, _ = self.login("borrower_b")
        first = self.make_request(borrower)
        second = self.make_request(borrower)
        self.assertEqual((first.status_code, second.status_code), (302, 302))
        count = self.get_db_row(
            "SELECT COUNT(*) AS count FROM borrow_requests WHERE item_id = ? AND borrower_id = ? AND status = 'pending'",
            (self.item_id, self.borrower_b_id),
        )["count"]
        self.assertEqual(count, 1)

        with app.app_context():
            with self.assertRaises(sqlite3.IntegrityError):
                get_db().execute(
                    """
                    INSERT INTO borrow_requests
                        (item_id, borrower_id, owner_id, proposed_return_date, status)
                    VALUES (?, ?, ?, ?, 'pending')
                    """,
                    (
                        self.item_id,
                        self.borrower_b_id,
                        self.owner_id,
                        (date.today() + timedelta(days=3)).isoformat(),
                    ),
                )
            get_db().rollback()

    def test_borrower_cannot_request_own_item(self):
        owner, _ = self.login("owner")
        response = self.make_request(owner)
        self.assertEqual(response.status_code, 403)
        count = self.get_db_row("SELECT COUNT(*) AS count FROM borrow_requests")["count"]
        self.assertEqual(count, 0)

    def test_ownership_checks_cover_all_request_actions(self):
        pending_id = self.add_request(self.borrower_b_id)
        with app.app_context():
            database = get_db()
            database.execute(
                """
                INSERT INTO items (owner_id, name, category, location, status)
                VALUES (?, 'Already lent item', 'Books', 'Lab', 'borrowed')
                """,
                (self.owner_id,),
            )
            borrowed_item_id = database.execute(
                "SELECT id FROM items WHERE name = 'Already lent item'"
            ).fetchone()["id"]
            database.commit()
        approved_id = self.add_request(self.borrower_b_id, status="approved", item_id=borrowed_item_id)
        owner, _ = self.login("owner")
        borrower, _ = self.login("borrower_b")
        other, _ = self.login("borrower_c")

        self.assertEqual(self.authorized_post(other, f"/requests/{pending_id}/approve").status_code, 404)
        self.assertEqual(self.authorized_post(other, f"/requests/{pending_id}/reject").status_code, 404)
        self.assertEqual(self.authorized_post(other, f"/requests/{pending_id}/cancel").status_code, 404)
        self.assertEqual(self.authorized_post(other, f"/requests/{approved_id}/report-return").status_code, 404)
        self.assertEqual(self.authorized_post(other, f"/requests/{approved_id}/confirm-return").status_code, 404)
        self.assertEqual(self.authorized_post(borrower, f"/requests/{approved_id}/confirm-return").status_code, 404)
        self.assertEqual(self.authorized_post(owner, f"/requests/{approved_id}/report-return").status_code, 404)
        self.assertEqual(self.authorized_post(owner, f"/requests/{pending_id}/cancel").status_code, 404)

    def test_csrf_rejects_post_without_token(self):
        borrower, _ = self.login("borrower_b")
        response = borrower.post(
            f"/items/{self.item_id}/request",
            data={"proposed_return_date": (date.today() + timedelta(days=2)).isoformat()},
        )
        self.assertEqual(response.status_code, 400)
        count = self.get_db_row("SELECT COUNT(*) AS count FROM borrow_requests")["count"]
        self.assertEqual(count, 0)

    def test_return_date_validation_rejects_invalid_dates(self):
        borrower, _ = self.login("borrower_b")
        invalid_dates = (
            (date.today() - timedelta(days=1)).isoformat(),
            date.today().isoformat(),
            "2026-02-30",
            (date.today() + timedelta(days=31)).isoformat(),
        )
        for return_date in invalid_dates:
            with self.subTest(return_date=return_date):
                self.assertEqual(
                    self.make_request(borrower, return_date=return_date).status_code, 302
                )
        count = self.get_db_row("SELECT COUNT(*) AS count FROM borrow_requests")["count"]
        self.assertEqual(count, 0)

    def test_two_step_return_flow(self):
        borrower, _ = self.login("borrower_b")
        self.assertEqual(self.make_request(borrower).status_code, 302)
        request_id = self.get_db_row(
            "SELECT id FROM borrow_requests WHERE borrower_id = ?", (self.borrower_b_id,)
        )["id"]
        owner, _ = self.login("owner")
        self.assertEqual(self.authorized_post(owner, f"/requests/{request_id}/approve").status_code, 302)
        approved = self.get_db_row(
            "SELECT status, due_date, return_reported_at FROM borrow_requests WHERE id = ?",
            (request_id,),
        )
        self.assertEqual((approved["status"], approved["return_reported_at"]), ("approved", None))
        self.assertIsNotNone(approved["due_date"])

        self.assertEqual(
            self.authorized_post(borrower, f"/requests/{request_id}/report-return").status_code, 302
        )
        reported = self.get_db_row(
            "SELECT status, return_reported_at FROM borrow_requests WHERE id = ?", (request_id,)
        )
        self.assertEqual(reported["status"], "approved")
        self.assertIsNotNone(reported["return_reported_at"])
        self.assertEqual(
            self.authorized_post(owner, f"/requests/{request_id}/confirm-return").status_code, 302
        )
        returned = self.get_db_row(
            "SELECT status, returned_at FROM borrow_requests WHERE id = ?", (request_id,)
        )
        item = self.get_db_row("SELECT status FROM items WHERE id = ?", (self.item_id,))
        self.assertEqual(returned["status"], "returned")
        self.assertIsNotNone(returned["returned_at"])
        self.assertEqual(item["status"], "available")
        self.assertEqual(
            self.authorized_post(borrower, f"/requests/{request_id}/report-return").status_code, 302
        )
        self.assertEqual(
            self.authorized_post(owner, f"/requests/{request_id}/confirm-return").status_code, 302
        )
        final_updated_at = self.get_db_row(
            "SELECT updated_at FROM borrow_requests WHERE id = ?", (request_id,)
        )["updated_at"]
        self.assertEqual(
            self.get_db_row("SELECT status FROM items WHERE id = ?", (self.item_id,))["status"],
            "available",
        )
        self.assertEqual(
            self.get_db_row(
                "SELECT returned_at FROM borrow_requests WHERE id = ?", (request_id,)
            )["returned_at"],
            returned["returned_at"],
        )
        self.assertEqual(
            self.get_db_row(
                "SELECT updated_at FROM borrow_requests WHERE id = ?", (request_id,)
            )["updated_at"],
            final_updated_at,
        )

    def test_security_headers_cookie_settings_and_error_pages(self):
        client, login_response = self.login("owner")
        cookies = "\n".join(login_response.headers.getlist("Set-Cookie"))
        self.assertIn("HttpOnly", cookies)
        self.assertIn("SameSite=Lax", cookies)
        self.assertNotIn("Secure", cookies)
        self.assertEqual(app.config["SESSION_COOKIE_HTTPONLY"], True)
        self.assertEqual(app.config["SESSION_COOKIE_SAMESITE"], "Lax")
        self.assertEqual(app.config["PERMANENT_SESSION_LIFETIME"].total_seconds(), 8 * 60 * 60)

        response = client.get("/missing-phase5-page")
        self.assertEqual(response.status_code, 404)
        self.assertIn(b"Page not found", response.data)
        for header in (
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Content-Security-Policy",
        ):
            self.assertIn(header, response.headers)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

        app.config["PROPAGATE_EXCEPTIONS"] = False
        server_error = client.get("/__phase5_test_error")
        self.assertEqual(server_error.status_code, 500)
        self.assertIn(b"Something went wrong", server_error.data)
        self.assertIn("Content-Security-Policy", server_error.headers)
        app.config["PROPAGATE_EXCEPTIONS"] = None

    def test_secure_cookie_setting_can_be_enabled(self):
        app.config["SESSION_COOKIE_SECURE"] = True
        try:
            _, response = self.login("owner")
            cookie_header = "\n".join(response.headers.getlist("Set-Cookie"))
            self.assertIn("Secure", cookie_header)
        finally:
            app.config["SESSION_COOKIE_SECURE"] = False

    def test_login_rate_limit_and_external_next_is_ignored(self):
        client = app.test_client()
        csrf_token = self.csrf_token(client, "/login?next=https://attacker.example")

        def bad_login():
            return client.post(
                "/login",
                data={
                    "identity": "borrower_b",
                    "password": "incorrect-password",
                    "csrf_token": csrf_token,
                },
            )

        clock = [100.0]
        with patch("app.time.monotonic", side_effect=lambda: clock[0]):
            for _ in range(5):
                response = bad_login()
                self.assertEqual(response.status_code, 401)
            locked = client.post(
                "/login",
                data={
                    "identity": "borrower_b",
                    "password": PASSWORD,
                    "csrf_token": csrf_token,
                },
            )
            self.assertEqual(locked.status_code, 429)
            self.assertIn(b"Too many login attempts. Try again later.", locked.data)

            clock[0] += 15 * 60
            allowed_after_lockout = bad_login()
            self.assertEqual(allowed_after_lockout.status_code, 401)

            LOGIN_FAILURES.clear()
            bad_login()
            clock[0] += 15 * 60 + 1
            bad_login()
            for _ in range(3):
                bad_login()
            not_yet_locked = bad_login()
            self.assertEqual(not_yet_locked.status_code, 401)
            window_lock = client.post(
                "/login",
                data={
                    "identity": "borrower_b",
                    "password": PASSWORD,
                    "csrf_token": csrf_token,
                },
            )
            self.assertEqual(window_lock.status_code, 429)
            clock[0] += 15 * 60 - 1
            still_locked = client.post(
                "/login",
                data={
                    "identity": "borrower_b",
                    "password": PASSWORD,
                    "csrf_token": csrf_token,
                },
            )
            self.assertEqual(still_locked.status_code, 429)
            clock[0] += 1
            expired = bad_login()
            self.assertEqual(expired.status_code, 401)

        LOGIN_FAILURES.clear()
        redirected_client, response = self.login(
            "borrower_b", client=client, next_url="https://attacker.example"
        )
        self.assertIs(redirected_client, client)
        self.assertEqual(response.headers["Location"], "/dashboard")
        self.assertNotIn("attacker.example", response.headers["Location"])

    def test_admin_only_pages_and_cli_role_grant(self):
        anonymous = app.test_client()
        self.assertEqual(anonymous.get("/admin").status_code, 403)
        self.assertEqual(anonymous.get("/admin/items").status_code, 403)

        borrower, _ = self.login("borrower_b")
        response = borrower.get("/admin")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(b'href="/admin"', response.data)

        runner = app.test_cli_runner()
        result = runner.invoke(args=["make-admin", "owner"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Admin role granted", result.output)
        self.assertEqual(
            self.get_db_row(
                "SELECT is_admin FROM users WHERE username = 'owner'"
            )["is_admin"],
            1,
        )

        self.add_request(self.borrower_b_id, status="returned", returned=True)
        admin, _ = self.login("owner")
        dashboard = admin.get("/admin")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"total users", dashboard.data)
        self.assertIn(b"borrower_b", dashboard.data)
        self.assertIn(b"Items", dashboard.data)
        self.assertNotIn(b"password_hash", dashboard.data)
        item_page = admin.get("/admin/items")
        self.assertEqual(item_page.status_code, 200)
        self.assertIn(b"Test calculator", item_page.data)
        self.assertIn(b"owner", item_page.data)

    def test_admin_delete_checks_role_csrf_and_borrowed_confirmation(self):
        self.grant_admin()
        with app.app_context():
            database = get_db()
            database.execute(
                """
                INSERT INTO items (owner_id, name, category, location)
                VALUES (?, 'Disposable listing', 'Books', 'Library')
                """,
                (self.borrower_b_id,),
            )
            removable_id = database.execute(
                "SELECT id FROM items WHERE name = 'Disposable listing'"
            ).fetchone()["id"]
            database.execute(
                """
                INSERT INTO items (owner_id, name, category, location, status)
                VALUES (?, 'Borrowed listing', 'Books', 'Library', 'borrowed')
                """,
                (self.owner_id,),
            )
            borrowed_item_id = database.execute(
                "SELECT id FROM items WHERE name = 'Borrowed listing'"
            ).fetchone()["id"]
            database.commit()
        borrowed_request_id = self.add_request(
            self.borrower_c_id, status="approved", item_id=borrowed_item_id
        )
        with app.app_context():
            database = get_db()
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS admin_delete_audit (
                    request_id INTEGER,
                    old_status TEXT,
                    new_status TEXT,
                    returned_at TEXT
                )
                """
            )
            database.execute("DELETE FROM admin_delete_audit")
            database.execute(
                """
                CREATE TRIGGER IF NOT EXISTS record_admin_request_close
                BEFORE DELETE ON items
                BEGIN
                    INSERT INTO admin_delete_audit
                    SELECT id, status, 'deleted-with-item', returned_at
                    FROM borrow_requests
                    WHERE item_id = OLD.id;
                END
                """
            )
            database.commit()

        non_admin, _ = self.login("borrower_b")
        denied = self.authorized_post(
            non_admin, f"/admin/items/{removable_id}/delete"
        )
        self.assertEqual(denied.status_code, 403)
        self.assertIsNotNone(
            self.get_db_row("SELECT id FROM items WHERE id = ?", (removable_id,))
        )

        admin, _ = self.login("owner")
        missing_csrf = admin.post(f"/admin/items/{removable_id}/delete")
        self.assertEqual(missing_csrf.status_code, 400)
        self.assertIsNotNone(
            self.get_db_row("SELECT id FROM items WHERE id = ?", (removable_id,))
        )

        deleted = self.authorized_post(admin, f"/admin/items/{removable_id}/delete")
        self.assertEqual(deleted.status_code, 302)
        self.assertIsNone(
            self.get_db_row("SELECT id FROM items WHERE id = ?", (removable_id,))
        )

        refused = self.authorized_post(admin, f"/admin/items/{borrowed_item_id}/delete")
        self.assertEqual(refused.status_code, 302)
        self.assertIsNotNone(
            self.get_db_row("SELECT id FROM items WHERE id = ?", (borrowed_item_id,))
        )
        self.assertIsNotNone(
            self.get_db_row(
                "SELECT id FROM borrow_requests WHERE id = ?", (borrowed_request_id,)
            )
        )
        confirmed = self.authorized_post(
            admin,
            f"/admin/items/{borrowed_item_id}/delete",
            {"confirm_borrowed_delete": "yes"},
        )
        self.assertEqual(confirmed.status_code, 302)
        self.assertIsNone(
            self.get_db_row("SELECT id FROM items WHERE id = ?", (borrowed_item_id,))
        )
        self.assertIsNone(
            self.get_db_row(
                "SELECT id FROM borrow_requests WHERE id = ?", (borrowed_request_id,)
            )
        )
        audit = self.get_db_row(
            """
            SELECT old_status, new_status, returned_at
            FROM admin_delete_audit WHERE request_id = ?
            """,
            (borrowed_request_id,),
        )
        self.assertEqual((audit["old_status"], audit["new_status"]), ("returned", "deleted-with-item"))
        self.assertIsNotNone(audit["returned_at"])

    def test_owner_delete_rule_is_unchanged(self):
        with app.app_context():
            database = get_db()
            database.execute(
                """
                INSERT INTO items (owner_id, name, category, location)
                VALUES (?, 'Owner removable item', 'Books', 'Library')
                """,
                (self.borrower_b_id,),
            )
            owner_item_id = database.execute(
                "SELECT id FROM items WHERE name = 'Owner removable item'"
            ).fetchone()["id"]
            database.commit()
        approved_id = self.add_request(
            self.borrower_c_id, status="approved", item_id=self.item_id
        )
        owner_client, _ = self.login("borrower_b")
        other_item_delete = self.authorized_post(
            owner_client, f"/items/{self.item_id}/delete"
        )
        self.assertEqual(other_item_delete.status_code, 404)
        own_delete = self.authorized_post(
            owner_client, f"/items/{owner_item_id}/delete"
        )
        self.assertEqual(own_delete.status_code, 302)
        self.assertIsNone(
            self.get_db_row("SELECT id FROM items WHERE id = ?", (owner_item_id,))
        )

        actual_owner, _ = self.login("owner")
        borrowed_delete = self.authorized_post(
            actual_owner, f"/items/{self.item_id}/delete"
        )
        self.assertEqual(borrowed_delete.status_code, 302)
        self.assertIsNotNone(
            self.get_db_row("SELECT id FROM items WHERE id = ?", (self.item_id,))
        )
        self.assertIsNotNone(
            self.get_db_row("SELECT id FROM borrow_requests WHERE id = ?", (approved_id,))
        )

    def test_registration_invite_code_and_no_web_admin_assignment(self):
        app.config["INVITE_CODE"] = "campus-invite"
        try:
            client = app.test_client()
            page = client.get("/register")
            self.assertIn(b'name="invite_code"', page.data)
            csrf_token = CSRF_PATTERN.search(page.data).group(1).decode()
            common = {
                "username": "newstudent",
                "email": "newstudent@example.test",
                "password": PASSWORD,
                "confirm_password": PASSWORD,
                "is_admin": "1",
                "csrf_token": csrf_token,
            }
            denied = client.post("/register", data=common)
            self.assertEqual(denied.status_code, 400)
            accepted = client.post(
                "/register",
                data={**common, "invite_code": "campus-invite"},
            )
            self.assertEqual(accepted.status_code, 302)
            new_user = self.get_db_row(
                "SELECT is_admin FROM users WHERE username = 'newstudent'"
            )
            self.assertIsNotNone(new_user)
            self.assertEqual(new_user["is_admin"], 0)
        finally:
            app.config["INVITE_CODE"] = None

    def test_registration_without_invite_code_remains_open(self):
        app.config["INVITE_CODE"] = None
        client = app.test_client()
        page = client.get("/register")
        self.assertNotIn(b'name="invite_code"', page.data)
        csrf_token = CSRF_PATTERN.search(page.data).group(1).decode()
        response = client.post(
            "/register",
            data={
                "username": "openstudent",
                "email": "openstudent@example.test",
                "password": PASSWORD,
                "confirm_password": PASSWORD,
                "csrf_token": csrf_token,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self.get_db_row(
                "SELECT is_admin FROM users WHERE username = 'openstudent'"
            )["is_admin"],
            0,
        )

    def test_admin_column_migration_is_idempotent_and_preserves_existing_user(self):
        old_database = tempfile.NamedTemporaryFile(
            prefix=".borrowbuddy-old-schema-",
            suffix=".sqlite",
            dir=INSTANCE_PATH,
            delete=False,
        )
        old_database_path = old_database.name
        old_database.close()
        try:
            with closing(sqlite3.connect(old_database_path)) as database:
                database.execute(
                    """
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        email TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                database.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    ("existinguser", "existing@example.test", "hash-not-read"),
                )
                database.commit()
            original_path = app.config["DATABASE"]
            try:
                app.config["DATABASE"] = old_database_path
                from db import init_db

                init_db(app)
                init_db(app)
            finally:
                app.config["DATABASE"] = original_path

            with closing(sqlite3.connect(old_database_path)) as database:
                columns = {row[1] for row in database.execute("PRAGMA table_info(users)")}
                self.assertIn("is_admin", columns)
                self.assertEqual(
                    database.execute(
                        "SELECT COUNT(*), MIN(is_admin) FROM users"
                    ).fetchone(),
                    (1, 0),
                )
                self.assertEqual(
                    database.execute(
                        "SELECT username, email FROM users WHERE id = 1"
                    ).fetchone(),
                    ("existinguser", "existing@example.test"),
                )
        finally:
            remove_sqlite_files(old_database_path)

    def test_deployment_environment_configuration_is_documented_and_loaded(self):
        self.assertEqual(INITIAL_DATABASE_CONFIG, str(BOOTSTRAP_DATABASE))
        self.assertEqual(INITIAL_SECRET_KEY_CONFIG, "test-only-secret-key")
        self.assertEqual(Path(app.instance_path), INSTANCE_PATH.resolve())
        self.assertFalse(app.config["DEBUG"])

        requirements = (PROJECT_ROOT / "requirements.txt").read_text()
        readme = (PROJECT_ROOT / "README.md").read_text()
        self.assertRegex(requirements, r"(?m)^gunicorn==")
        self.assertIn("## Deploy", readme)
        self.assertIn("BORROWBUDDY_SECRET_KEY", readme)
        self.assertIn("BORROWBUDDY_DATABASE", readme)
        self.assertIn("BORROWBUDDY_INSTANCE_PATH", readme)

    def test_user_supplied_html_is_autoescaped(self):
        with app.app_context():
            database = get_db()
            cursor = database.execute(
                """
                INSERT INTO items (owner_id, name, description, category, location)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    self.owner_id,
                    "<script>alert(1)</script>",
                    "A safe description",
                    "Books",
                    "Library",
                ),
            )
            item_id = cursor.lastrowid
            database.commit()
        response = app.test_client().get(f"/items/{item_id}")
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", response.data)
        self.assertNotIn(b"<script>alert(1)</script>", response.data)


if __name__ == "__main__":
    unittest.main()
