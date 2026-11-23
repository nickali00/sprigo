"""Per-account SQLite databases for standalone Sprigo Web."""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import hmac
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path

SESSION_SECONDS = 30 * 24 * 3600
MAX_ACCOUNTS = 32
MAX_IMPORT_DB = 8 * 1024 * 1024
MAX_DB_BYTES = 64 * 1024 * 1024
MAX_ROWS = 5000
MAX_RESULT_BYTES = 8 * 1024 * 1024
QUERY_SECONDS = 3
USERNAME = re.compile(r"[A-Za-z0-9_.-]{3,32}\Z")
DENIED = {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_CREATE_VTABLE,
          sqlite3.SQLITE_DROP_VTABLE}


class AccountError(ValueError):
    pass


class StaleRevision(AccountError):
    pass


class Accounts:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.db_dir = root / 'accounts'
        self.db_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db_dir.chmod(0o700)
        self.meta = root / 'accounts.sqlite3'
        self.lock = threading.RLock()
        self.db_locks: dict[str, threading.Lock] = {}
        with self._meta() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS accounts(
                    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    salt BLOB NOT NULL, password_hash BLOB NOT NULL, created_at INTEGER NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS sessions(
                    token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    expires_at INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS sessions_account ON sessions(account_id);
            ''')
            if 'revision' not in [row[1] for row in db.execute('PRAGMA table_info(accounts)')]:
                db.execute('ALTER TABLE accounts ADD COLUMN revision INTEGER NOT NULL DEFAULT 0')
        self.meta.chmod(0o600)

    @contextmanager
    def _meta(self):
        db = sqlite3.connect(self.meta, timeout=20)
        try:
            db.execute('PRAGMA foreign_keys=ON')
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _hash(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 400_000)

    def _session(self, db: sqlite3.Connection, account_id: str) -> str:
        db.execute('DELETE FROM sessions WHERE expires_at <= ?', (int(time.time()),))
        token = secrets.token_urlsafe(32)
        db.execute('INSERT INTO sessions VALUES (?, ?, ?)',
                   (hashlib.sha256(token.encode()).hexdigest(), account_id, int(time.time()) + SESSION_SECONDS))
        return token

    def register(self, username: str, password: str, import_db: bytes | None = None) -> str:
        if not isinstance(username, str) or not isinstance(password, str):
            raise AccountError('Invalid account details')
        username = username.strip()
        if not USERNAME.fullmatch(username):
            raise AccountError('Username: 3–32 letters, numbers, dots, dashes or underscores')
        if not 8 <= len(password) <= 128:
            raise AccountError('Password must be 8–128 characters')
        if import_db is not None and (len(import_db) < 100 or len(import_db) > MAX_IMPORT_DB or not import_db.startswith(b'SQLite format 3\0')):
            raise AccountError('Invalid local database')
        account_id = secrets.token_hex(16)
        path = self.db_dir / f'{account_id}.sqlite3'
        if import_db is not None:
            path.write_bytes(import_db)
            try:
                db = sqlite3.connect(path)
                try:
                    if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                        raise AccountError('Local database integrity check failed')
                    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='profiles'").fetchone():
                        raise AccountError('Local database has no Sprigo profiles')
                finally:
                    db.close()
            except Exception:
                path.unlink(missing_ok=True)
                raise
        else:
            sqlite3.connect(path).close()
        path.chmod(0o600)
        salt = secrets.token_bytes(16)
        try:
            with self.lock, self._meta() as db:
                if db.execute('SELECT count(*) FROM accounts').fetchone()[0] >= MAX_ACCOUNTS:
                    raise AccountError('Account limit reached')
                db.execute('INSERT INTO accounts(id, username, salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
                           (account_id, username, salt, self._hash(password, salt), int(time.time())))
                token = self._session(db, account_id)
            return token
        except sqlite3.IntegrityError as exc:
            path.unlink(missing_ok=True)
            raise AccountError('Username already exists') from exc
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def login(self, username: str, password: str) -> str:
        if not isinstance(username, str) or not isinstance(password, str):
            raise AccountError('Invalid username or password')
        with self.lock, self._meta() as db:
            row = db.execute('SELECT id, salt, password_hash FROM accounts WHERE username = ?', (username.strip(),)).fetchone()
            # Hash a dummy secret too, so missing usernames take comparable time.
            candidate = self._hash(password, row[1] if row else bytes(16))
            expected = row[2] if row else bytes(len(candidate))
            if not hmac.compare_digest(candidate, expected) or row is None or not password:
                raise AccountError('Invalid username or password')
            return self._session(db, row[0])

    def session(self, token: str | None) -> tuple[str, str] | None:
        if not token:
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.lock, self._meta() as db:
            row = db.execute('''SELECT accounts.id, accounts.username FROM sessions
                JOIN accounts ON accounts.id = sessions.account_id
                WHERE token_hash = ? AND expires_at > ?''', (digest, int(time.time()))).fetchone()
            return (row[0], row[1]) if row else None

    def revision(self, account_id: str) -> int:
        with self.lock, self._meta() as db:
            row = db.execute('SELECT revision FROM accounts WHERE id = ?', (account_id,)).fetchone()
            return row[0] if row else 0

    def logout(self, token: str | None):
        if token:
            with self.lock, self._meta() as db:
                db.execute('DELETE FROM sessions WHERE token_hash = ?', (hashlib.sha256(token.encode()).hexdigest(),))

    @staticmethod
    def _bindings(statement: str, args: list):
        # Python sqlite3 treats $1 as a named parameter, unlike sql.js.
        return {str(i + 1): value for i, value in enumerate(args)} if re.search(r'\$[1-9][0-9]*', statement) else args

    def sql(self, account_id: str, kind: str, statement: str, args: list, expected_revision: int | None = None):
        if kind not in ('select', 'execute') or not isinstance(statement, str) or len(statement) > 100_000 or not isinstance(args, list) or len(args) > 1000:
            raise AccountError('Invalid SQL request')
        if expected_revision is not None and (type(expected_revision) is not int or expected_revision < 0):
            raise AccountError('Invalid revision')
        lead = statement.lstrip().split(None, 1)[0].lower().rstrip(';') if statement.strip() else ''
        if kind == 'select' and lead not in ('select', 'with', 'pragma'):
            raise AccountError('Invalid read query')
        if kind == 'select' and lead == 'pragma' and statement.strip().lower().rstrip(';') != 'pragma user_version':
            raise AccountError('SQL operation not allowed')
        if lead in ('attach', 'detach', 'vacuum'):
            raise AccountError('SQL operation not allowed')
        path = self.db_dir / f'{account_id}.sqlite3'
        with self.lock:
            lock = self.db_locks.setdefault(account_id, threading.Lock())
        with lock:
            if kind == 'execute' and expected_revision is not None and self.revision(account_id) != expected_revision:
                raise StaleRevision('Account changed on another device; reload before writing')
            db = sqlite3.connect(path, timeout=20)
            db.row_factory = sqlite3.Row
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4 * 1024 * 1024)
            page_size = db.execute('PRAGMA page_size').fetchone()[0]
            db.execute(f'PRAGMA max_page_count={MAX_DB_BYTES // page_size}')
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA busy_timeout=5000')
            if kind == 'select':
                db.execute('PRAGMA query_only=ON')
            deadline = time.monotonic() + QUERY_SECONDS
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            bindings = self._bindings(statement, args)
            def authorize(action, arg1, arg2, db_name, source):
                if action in DENIED:
                    return sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_PRAGMA and (arg1 or '').lower() != 'user_version':
                    return sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_FUNCTION and (arg2 or '').lower() == 'load_extension':
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            db.set_authorizer(authorize)
            try:
                if kind == 'select':
                    rows = []
                    total = 0
                    for row in db.execute(statement, bindings):
                        if len(rows) >= MAX_ROWS:
                            raise AccountError('Query returned too many rows')
                        item = dict(row)
                        total += sum(len(str(value).encode('utf-8')) for value in item.values())
                        if total > MAX_RESULT_BYTES:
                            raise AccountError('Query result too large')
                        rows.append(item)
                    return rows
                before = db.total_changes
                if args:
                    db.execute(statement, bindings)
                elif ';' in statement.strip().rstrip(';'):
                    db.executescript(statement)
                else:
                    db.execute(statement)
                last_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
                db.commit()
                changed = db.total_changes > before or lead in ('begin', 'create', 'alter', 'drop')
                if changed:
                    with self.lock, self._meta() as meta:
                        meta.execute('UPDATE accounts SET revision = revision + 1 WHERE id = ?', (account_id,))
                return {'lastInsertId': last_id, 'revision': self.revision(account_id)}
            finally:
                db.close()
