# BorrowBuddy

BorrowBuddy is a campus item-lending app. It provides account access, item
listings, browsing/search, and Phase 3 borrow requests. Returns, return
confirmation, and overdue tracking are not implemented.

## Requirements

- Python 3
- macOS Terminal (or another shell)

Flask and Flask-WTF are the third-party Python dependencies. SQLite is included
with Python.

## First-time setup on macOS

From the BorrowBuddy project folder, create a project-local virtual environment
and install the app dependencies:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Set a private secret key in this Terminal session before starting the app. It
signs the browser's login session; do not commit it or share it:

```sh
export BORROWBUDDY_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Open <http://127.0.0.1:5001>. The app listens on port 5001 so it does not
conflict with macOS AirPlay using port 5000. Stop the local development server
with Control-C.
The generated key remains available in this Terminal session; set it again in a
new session (existing login cookies will no longer be valid after changing it).

## Database

On startup, BorrowBuddy creates `instance/borrowbuddy.sqlite` and creates any
missing tables. The `instance/` folder contains local data and is ignored by
Git. To use a different database file for local testing, set
`BORROWBUDDY_DATABASE` to its path before starting the app.

The schema contains `users`, `items`, and `borrow_requests`, with primary/foreign
keys, uniqueness and value checks, and creation/update timestamps. Items include
a location; borrow requests include proposed return, due, and returned
timestamps. The database is created when the app starts.

## Features

- Register with a unique username and email; usernames are 3-30 letters,
  numbers, or underscores.
- Passwords must be 8-128 characters and are stored as Werkzeug password hashes,
  never as plain text.
- Every POST form includes a CSRF token. Flask-WTF checks that the token matches
  the user's signed session before accepting the request. A different website
  cannot normally read that session token, so it cannot silently submit an
  authenticated action on the user's behalf.
- Log in using a username or email. Login errors do not disclose whether the
  account exists.
- Log out using a POST form and access a dashboard only after logging in.
- SQL values are passed through SQLite placeholders rather than inserted into
  query strings.
- Add and manage your items from **My items**. Item categories and condition
  values are restricted to the choices shown in the form.
- Browse and filter available items listed by other users. Search treats `%`
  and `_` as ordinary characters rather than wildcard operators.
- Item edit, delete, and availability actions verify ownership on the server.
  Availability can be switched only between `available` and `unavailable`;
  owners cannot set an item to `borrowed`.
- Dashboard totals are counted from the SQLite database.
- Borrow requests use a proposed return date no more than 30 days ahead.
  Approval is an atomic transaction: it marks the item borrowed, sets the due
  date from the proposal, and rejects competing pending requests. Return and
  overdue handling are handled in two steps: the borrower reports a return and
  the item owner confirms it. Overdue status is calculated at query time rather
  than stored. Existing databases get the return-report timestamp column
  through an idempotent startup migration.
- Owners can approve or reject incoming pending requests; borrowers can cancel
  their own pending requests. The database's partial unique index permits only
  one pending request per borrower/item pair.

This is a beginner/local development app, not a production deployment. Before
putting it on the public internet, configure HTTPS, secure cookie settings,
production hosting, and operational safeguards.
