# BorrowBuddy

BorrowBuddy is a campus item-lending app built with Flask, SQLite, HTML, CSS,
vanilla JavaScript, and Jinja templates. It supports accounts, item listings,
borrow requests, two-step returns, and overdue indicators.

## Requirements

- Python 3
- macOS Terminal (or another shell)

Flask, Flask-WTF, and Gunicorn are the third-party Python dependencies. SQLite
is included with Python.

## First-time setup on macOS

From the BorrowBuddy project folder, create a project-local virtual environment
and install the dependencies:

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
with Control-C. The key remains available only in that Terminal session; set it
again in a new session (existing login cookies will no longer be valid after
changing it).

## Security settings

- Session cookies are HTTP-only, use `SameSite=Lax`, and are persistent for
  eight hours after login.
- Local HTTP is supported by default. For a deployment served entirely over
  HTTPS, set `BORROWBUDDY_COOKIE_SECURE=true` before starting the app so the
  browser sends session cookies only over HTTPS. Do not enable this for local
  plain-HTTP testing.
- Every response receives content-type, framing, referrer, and Content Security
  Policy headers. The policy permits the app's own CSS and JavaScript only.
- Five failed attempts for the same username and client IP within 15 minutes
  trigger a generic lockout message and a 15-minute lockout. The limiter is an
  in-memory dictionary: it needs no new dependency, but it resets when the
  process restarts and is not shared between multiple server workers.
- Login always redirects to the app's dashboard after success. It ignores
  caller-supplied redirect targets, preventing external open redirects.
- Jinja autoescapes HTML templates. Keep user-provided values in normal
  template expressions; do not mark untrusted content as safe.
- Custom 403, 404, and 500 pages use the BorrowBuddy design. Unexpected
  exception details remain in server logs instead of being shown to visitors.
- Admin status is granted only from the command line, never through a web form.
  Admins can review account/item summaries and manage listings. Deleting a
  borrowed item requires explicit confirmation because its request and return
  history is deleted with it.
- If `BORROWBUDDY_INVITE_CODE` is set, new registrations must supply that code.
  If it is unset, registration remains open.

## Database

On startup, BorrowBuddy creates `instance/borrowbuddy.sqlite` and creates any
missing tables. Existing databases receive the `return_reported_at` and
`is_admin` columns via idempotent migrations. The `instance/` folder contains
local data and is ignored by Git. Set `BORROWBUDDY_INSTANCE_PATH` to use a
different instance directory (for example, a host's persistent disk). Set
`BORROWBUDDY_DATABASE` to override the SQLite file path directly.

The schema contains `users`, `items`, and `borrow_requests`, with primary and
foreign keys, uniqueness and value checks, and creation/update timestamps. A
partial unique index permits only one pending request per borrower/item pair.

## Features

- Register with a unique username and email; usernames are 3-30 letters,
  numbers, or underscores. Passwords are stored as Werkzeug password hashes.
- Every POST form includes a Flask-WTF CSRF token. The app validates the token
  against the user's signed session before accepting the action.
- Log in using a username or email. Error messages do not disclose whether the
  account exists.
- Add and manage items. Categories and condition values are restricted to the
  choices shown in the form. Item edit/delete/availability actions verify
  ownership on the server.
- Browse and filter available items listed by other users. Search treats `%`
  and `_` as ordinary characters rather than wildcard operators.
- Borrow requests use a proposed return date no more than 30 days ahead.
  Approval is an atomic transaction: it marks the item borrowed, sets the due
  date from the proposal, and rejects competing pending requests.
- Returns use two steps: the borrower reports a return and the item owner
  confirms it. Overdue state is calculated at query time rather than stored.
- Dashboard and history totals are read from SQLite, not hard-coded.
- Admins are granted with `flask --app app make-admin <username>`. The command
  changes only an existing account; no web route can grant the role.

## Automated tests

Run the tests from the project folder with the virtual environment active:

```sh
python -m unittest discover -s tests -v
```

The tests use a temporary SQLite file inside `instance/` and remove it after
the test run. They never use or delete the normal `instance/borrowbuddy.sqlite`
database.

## Deploy

Use a host with a persistent writable disk for the SQLite database; ephemeral
container storage can lose user and lending data on redeploy. Configure:

- `BORROWBUDDY_SECRET_KEY`: a long random secret, kept private.
- `BORROWBUDDY_INSTANCE_PATH`: writable persistent directory for instance data.
- `BORROWBUDDY_DATABASE`: optional explicit SQLite file path; if unset, the app
  uses `borrowbuddy.sqlite` inside `BORROWBUDDY_INSTANCE_PATH`.
- `BORROWBUDDY_COOKIE_SECURE=true`: enable only when HTTPS is configured.
- `BORROWBUDDY_INVITE_CODE`: optional registration invite code; leave unset for
  open registration.

Install dependencies, then start the production WSGI server with:

```sh
gunicorn --bind 0.0.0.0:${PORT:-8000} app:app
```

The application keeps debug mode off. Run `flask --app app make-admin <username>`
from a secure deployment shell after the account exists to grant administrative
access. The in-memory login limiter is per process, so use one worker or add a
shared rate-limit store before scaling to multiple workers.
