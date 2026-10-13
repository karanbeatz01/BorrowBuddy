"""Small SQLite helpers for the BorrowBuddy app."""

import os
import sqlite3

from flask import current_app, g


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE
        CHECK (length(trim(username)) BETWEEN 3 AND 30),
    email TEXT NOT NULL COLLATE NOCASE UNIQUE
        CHECK (length(trim(email)) <= 254),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100),
    description TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    item_condition TEXT NOT NULL DEFAULT 'good'
        CHECK (item_condition IN ('new', 'good', 'fair', 'worn')),
    status TEXT NOT NULL DEFAULT 'available'
        CHECK (status IN ('available', 'unavailable', 'borrowed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS borrow_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    borrower_id INTEGER NOT NULL,
    owner_id INTEGER NOT NULL,
    proposed_return_date TEXT,
    due_date TEXT,
    returned_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled', 'returned')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (borrower_id <> owner_id),
    FOREIGN KEY (item_id) REFERENCES items (id) ON DELETE CASCADE,
    FOREIGN KEY (borrower_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_items_owner_id ON items (owner_id);
CREATE INDEX IF NOT EXISTS idx_borrow_requests_borrower_id
    ON borrow_requests (borrower_id);
CREATE INDEX IF NOT EXISTS idx_borrow_requests_item_id
    ON borrow_requests (item_id);
"""


def get_db():
    """Reuse one connection per request and enable SQLite foreign keys."""
    if "db" not in g:
        database_path = current_app.config["DATABASE"]
        os.makedirs(os.path.dirname(os.path.abspath(database_path)), exist_ok=True)
        g.db = sqlite3.connect(database_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    """Close the request's connection when Flask finishes the request."""
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db(app):
    """Create the schema if this is the first time the app is started."""
    database_path = app.config["DATABASE"]
    os.makedirs(os.path.dirname(os.path.abspath(database_path)), exist_ok=True)
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(SCHEMA)
        connection.commit()
    finally:
        connection.close()
