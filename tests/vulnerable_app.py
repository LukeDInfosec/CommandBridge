#!/usr/bin/env python3
"""A deliberately vulnerable application, for testing the scanner.

It exists to answer one question honestly: does the scanner find real bugs,
and does it stay quiet about the things that are fine? So it contains both —
seven planted vulnerabilities and, beside each, a correct implementation of
the same feature. A scan that reports the safe endpoints is as broken as one
that misses the vulnerable ones, and the test suite checks for both.

Planted, behind a login:

    /item?id=          SQL injection      string-concatenated SQLite query
    /search?q=         reflected XSS      unescaped into the page body
    /profile?nick=     reflected XSS      unescaped into an attribute
    /ping?host=        command injection  passed to a shell
    /download?file=    path traversal     open() on a caller-supplied path
    /render?tpl=       template injection {{ }} evaluated
    /go?next=          open redirection   Location taken from the query
    /account?user_id=  IDOR               no check that the record is yours
    /admin             forced browsing    no session check at all

Correct, and which the scanner must leave alone:

    /item_safe?id=     parameterised query
    /clean?q=          HTML-escaped reflection
    /profile_safe?nick= attribute-escaped reflection
    /go_safe?next=     allow-listed redirect
    /download_safe?f=  fixed map of names to files
    /jitter?q=         responds in a random 0.1–0.9s, to catch a scanner
                       that mistakes a slow endpoint for a timing oracle
    /wobble?q=         returns a different random number every time, to catch
                       one that mistakes an unstable page for a differential

Nothing here should ever be exposed to a network. It binds to 127.0.0.1 on a
port the caller chooses.
"""

from __future__ import annotations

import html
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

USERS = {"alice": {"password": "wonderland", "id": 1,
                   "email": "alice@example.com"},
         "bob": {"password": "builder", "id": 2, "email": "bob@example.com"}}

SESSIONS = {}
STORED_COMMENTS = []
SECRET_FILE = None


def _database():
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.execute("CREATE TABLE items (id INTEGER, name TEXT, owner TEXT)")
    connection.executemany(
        "INSERT INTO items VALUES (?,?,?)",
        [(1, "Blue widget", "alice"), (2, "Red widget", "alice"),
         (3, "Green widget", "bob")])
    connection.commit()
    return connection


DB = _database()
DB_LOCK = threading.Lock()

PAGE = """<!doctype html><html><head><title>{title}</title></head><body>
<nav><a href="/dashboard">Dashboard</a> <a href="/items">Items</a>
<a href="/search?q=test">Search</a> <a href="/tools">Tools</a>
<a href="/account?user_id={uid}">My account</a>
<a href="/comments">Comments</a>
<a href="/logout">Sign out</a></nav>
<h1>{title}</h1>{body}</body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "VulnApp/1.0"

    # ── plumbing ─────────────────────────────────────────────────────────
    def log_message(self, *args):
        pass

    def _send(self, code, body, headers=None, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _page(self, title, body, code=200, user=None):
        uid = USERS.get(user, {}).get("id", 1) if user else 1
        return self._send(code, PAGE.format(title=title, body=body, uid=uid))

    @property
    def _user(self):
        cookie = self.headers.get("Cookie", "")
        match = re.search(r"sid=([0-9a-f]+)", cookie)
        return SESSIONS.get(match.group(1)) if match else None

    def _query(self):
        parsed = urllib.parse.urlparse(self.path)
        return parsed.path, dict(urllib.parse.parse_qsl(parsed.query,
                                                        keep_blank_values=True))

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode(errors="replace") if length else ""
        if "json" in (self.headers.get("Content-Type") or ""):
            try:
                return json.loads(raw)
            except Exception:                           # noqa: BLE001
                return {}
        return dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))

    def _login_page(self, message=""):
        return self._send(200, f"""<!doctype html><html><head>
<title>Log in</title></head><body><h1>Log in</h1>
<p>Please log in to continue.</p>{message}
<form method="POST" action="/login">
<input type="hidden" name="csrf" value="{os.urandom(4).hex()}">
<input type="text" name="username"><input type="password" name="password">
<button type="submit">Log in</button></form></body></html>""")

    # ── routing ──────────────────────────────────────────────────────────
    def do_GET(self):
        path, query = self._query()
        user = self._user

        if path in ("/", "/login"):
            return self._login_page()
        if path == "/logout":
            cookie = re.search(r"sid=([0-9a-f]+)",
                               self.headers.get("Cookie", ""))
            if cookie:
                SESSIONS.pop(cookie.group(1), None)
            return self._send(302, b"", {"Location": "/login"})
        if path == "/about":
            return self._send(200, "<html><body><h1>About</h1>"
                                   "<p>A test application.</p></body></html>")

        # No session check at all — the planted forced-browsing hole.
        if path == "/admin":
            return self._send(200, "<html><body><h1>Administration</h1>"
                                   "<p>Server key: ADMIN-7741-KEY</p>"
                                   "<p>All users: alice, bob</p></body></html>")

        if user is None:
            return self._login_page()

        if path == "/dashboard":
            return self._page("Dashboard", f"""<p>Signed in as {user}.</p>
<ul><li><a href="/item?id=1">Blue widget</a></li>
<li><a href="/item?id=2">Red widget</a></li>
<li><a href="/item_safe?id=1">Blue widget (safe view)</a></li>
<li><a href="/tools">Tools</a></li>
<li><a href="/admin">Administration</a></li></ul>""", user=user)

        if path == "/items":
            return self._page("Items", """<ul>
<li><a href="/item?id=1">1</a></li><li><a href="/item?id=3">3</a></li>
<li><a href="/item_safe?id=2">2 (safe)</a></li></ul>""", user=user)

        if path == "/tools":
            return self._page("Tools", """
<form method="GET" action="/search"><input name="q" value="widget">
<button>Search</button></form>
<form method="GET" action="/profile"><input name="nick" value="alice">
<button>Set nickname</button></form>
<form method="GET" action="/ping"><input name="host" value="localhost">
<button>Ping</button></form>
<form method="GET" action="/download"><input name="file" value="notes.txt">
<button>Download</button></form>
<form method="GET" action="/render"><input name="tpl" value="hello">
<button>Render</button></form>
<form method="GET" action="/go"><input name="next" value="/dashboard">
<button>Go</button></form>
<form method="POST" action="/comment"><input name="body" value="nice">
<button>Comment</button></form>
<form method="GET" action="/clean"><input name="q" value="safe">
<button>Clean search</button></form>
<form method="GET" action="/jitter"><input name="q" value="x">
<button>Slow</button></form>
<form method="GET" action="/wobble"><input name="q" value="x">
<button>Unstable</button></form>""", user=user)

        # ── the planted holes ────────────────────────────────────────────
        if path == "/item":
            identifier = query.get("id", "1")
            # Scoped to the logged-in user, so the only planted access
            # control bug is the one in /account. The injection is still here.
            sql = (f"SELECT name, owner FROM items WHERE owner = '{user}' "
                   f"AND id = {identifier}")
            try:
                with DB_LOCK:
                    rows = DB.execute(sql).fetchall()
            except sqlite3.Error as exc:
                # A real application leaking the parser's complaint.
                # Escaped: the planted bug on this endpoint is the SQL
                # injection, not a reflection in its error page.
                safe = html.escape(identifier)
                return self._page("Item", f"<p>Database error: "
                                          f"near \"{safe}\": syntax "
                                          f"error — {html.escape(str(exc))}"
                                          f"</p>", 500, user)
            if not rows:
                return self._page("Item", "<p>No such item.</p>", 200, user)
            return self._page("Item", "".join(
                f"<p>Item: {name} (owner {owner})</p>" for name, owner in rows),
                user=user)

        if path == "/item_safe":
            try:
                with DB_LOCK:
                    rows = DB.execute(
                        "SELECT name FROM items WHERE owner = ? AND id = ?",
                        (user, int(query.get("id", "1") or 0))).fetchall()
            except (ValueError, sqlite3.Error):
                return self._page("Item", "<p>Invalid item.</p>", 400, user)
            return self._page("Item", "".join(f"<p>Item: {r[0]}</p>"
                                              for r in rows), user=user)

        if path == "/search":
            term = query.get("q", "")
            return self._page("Search", f"<p>Results for {term}</p>",
                              user=user)

        if path == "/clean":
            return self._page("Clean search",
                              f"<p>Results for {html.escape(query.get('q', ''))}"
                              f"</p>", user=user)

        if path == "/profile":
            nick = query.get("nick", "")
            return self._page("Profile",
                              f'<input type="text" name="nick" value="{nick}">',
                              user=user)

        if path == "/profile_safe":
            nick = html.escape(query.get("nick", ""), quote=True)
            return self._page("Profile",
                              f'<input type="text" name="nick" value="{nick}">',
                              user=user)

        if path == "/ping":
            host = query.get("host", "localhost")
            try:
                output = subprocess.run(f"echo pinging {host}", shell=True,
                                        capture_output=True, text=True,
                                        timeout=30).stdout
            except Exception as exc:                    # noqa: BLE001
                output = f"failed: {exc}"
            return self._page("Ping", f"<pre>{output}</pre>", user=user)

        if path == "/download":
            name = query.get("file", "notes.txt")
            try:
                data = Path(SECRET_FILE).parent.joinpath(name).read_text(
                    errors="replace")
            except Exception:                           # noqa: BLE001
                try:
                    data = Path(name).read_text(errors="replace")
                except Exception as exc:                # noqa: BLE001
                    # Escaped: the planted bug here is the traversal, not a
                    # reflection in the error page.
                    return self._page("Download",
                                      f"<p>Not found: {html.escape(str(exc))}"
                                      f"</p>", 404, user)
            return self._send(200, data, ctype="text/plain; charset=utf-8")

        if path == "/download_safe":
            allowed = {"notes": SECRET_FILE}
            chosen = allowed.get(query.get("f", ""))
            if not chosen:
                return self._page("Download", "<p>Unknown file.</p>", 404, user)
            return self._send(200, Path(chosen).read_text(),
                              ctype="text/plain; charset=utf-8")

        if path == "/render":
            template = query.get("tpl", "hello")
            rendered = re.sub(
                r"\{\{(.+?)\}\}",
                lambda m: str(_evaluate(m.group(1))), template)
            return self._page("Render", f"<p>{rendered}</p>", user=user)

        if path == "/go":
            return self._send(302, b"",
                              {"Location": query.get("next", "/dashboard")})

        if path == "/go_safe":
            destination = query.get("next", "/dashboard")
            if not destination.startswith("/") or destination.startswith("//"):
                destination = "/dashboard"
            return self._send(302, b"", {"Location": destination})

        if path == "/account":
            wanted = query.get("user_id", "")
            for name, record in USERS.items():
                if str(record["id"]) == str(wanted):
                    return self._page(
                        "Account",
                        f"<p>Name: {name}</p><p>Email: {record['email']}</p>"
                        f"<p>Account number: {record['id']}00042</p>",
                        user=user)
            return self._page("Account", "<p>No such account.</p>", 404, user)

        if path == "/comments":
            return self._page("Comments", "".join(
                f"<div>{c}</div>" for c in STORED_COMMENTS) or "<p>None.</p>",
                user=user)

        if path == "/jitter":
            time.sleep(random.uniform(0.1, 0.9))
            return self._page("Slow", f"<p>Took a while: "
                                      f"{html.escape(query.get('q', ''))}</p>",
                              user=user)

        if path == "/wobble":
            return self._page("Unstable",
                              f"<p>Random: {random.randint(1, 10**9)}</p>"
                              f"<p>{html.escape(query.get('q', ''))}</p>",
                              user=user)

        return self._page("Not found", "<p>No such page.</p>", 404, user)

    def do_POST(self):
        path, _ = self._query()
        fields = self._body()

        if path == "/login":
            record = USERS.get(fields.get("username", ""))
            if record and record["password"] == fields.get("password"):
                sid = os.urandom(8).hex()
                SESSIONS[sid] = fields["username"]
                return self._send(
                    302, b"", {"Location": "/dashboard",
                               "Set-Cookie": f"sid={sid}; Path=/"})
            return self._login_page("<p>Wrong credentials.</p>")

        if self._user is None:
            return self._login_page()

        if path == "/comment":
            STORED_COMMENTS.append(fields.get("body", "")[:400])
            return self._page("Comments", "<p>Saved.</p>", user=self._user)

        return self._page("Not found", "<p>No such page.</p>", 404, self._user)

    do_HEAD = do_GET


def _evaluate(expression):
    """The template engine's mistake: evaluating what it was given."""
    try:
        return eval(expression, {"__builtins__": {}}, {})   # noqa: S307
    except Exception:                                       # noqa: BLE001
        return ""


def start(port=0):
    """Start the application on localhost. Returns (server, base_url)."""
    global SECRET_FILE
    directory = Path(tempfile.mkdtemp())
    SECRET_FILE = str(directory / "notes.txt")
    Path(SECRET_FILE).write_text("nothing interesting here\n")
    SESSIONS.clear()
    STORED_COMMENTS.clear()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


if __name__ == "__main__":
    server, base = start(int(sys.argv[1]) if len(sys.argv) > 1 else 8099)
    print(f"vulnerable app on {base} — alice / wonderland")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()
