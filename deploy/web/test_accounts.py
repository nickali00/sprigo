"""Security and compatibility checks for shared Sprigo Web accounts."""
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path

from accounts import Accounts, AccountError, StaleRevision, MAX_ROWS


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.accounts = Accounts(Path(self.tmp.name))

    def test_real_app_placeholders_and_isolation(self):
        first = self.accounts.session(self.accounts.register('first', 'long-password-1'))[0]
        second = self.accounts.session(self.accounts.register('second', 'long-password-2'))[0]
        self.accounts.sql(first, 'execute', 'CREATE TABLE notes(message TEXT)', [])
        self.accounts.sql(first, 'execute', 'INSERT INTO notes(message) VALUES ($1)', ['private'])
        self.assertEqual(self.accounts.sql(first, 'select', 'SELECT message FROM notes WHERE message = $1', ['private']), [{'message': 'private'}])
        self.assertEqual(self.accounts.sql(second, 'select', 'SELECT name FROM sqlite_master WHERE name = $1', ['notes']), [])
        self.assertGreaterEqual(self.accounts.revision(first), 2)
        with self.assertRaises(AccountError):
            self.accounts.login('first', 'wrong')
        self.assertEqual(self.accounts.session(self.accounts.login('first', 'long-password-1'))[0], first)

    def test_read_query_cannot_write_and_rows_are_capped(self):
        account = self.accounts.session(self.accounts.register('learner', 'long-password-3'))[0]
        self.accounts.sql(account, 'execute', 'CREATE TABLE notes(message TEXT)', [])
        revision = self.accounts.revision(account)
        with self.assertRaises(sqlite3.DatabaseError):
            self.accounts.sql(account, 'select', "WITH item AS (SELECT 'bad') INSERT INTO notes SELECT * FROM item", [])
        self.assertEqual(self.accounts.sql(account, 'select', 'SELECT count(*) AS n FROM notes', []), [{'n': 0}])
        self.assertEqual(self.accounts.revision(account), revision)
        with self.assertRaises(AccountError):
            self.accounts.sql(account, 'select', f'WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x < {MAX_ROWS+1}) SELECT x FROM n', [])

    def test_stale_write_is_rejected(self):
        account = self.accounts.session(self.accounts.register('single', 'long-password-5'))[0]
        self.accounts.sql(account, 'execute', 'CREATE TABLE notes(message TEXT)', [], 0)
        with self.assertRaises(StaleRevision):
            self.accounts.sql(account, 'execute', 'INSERT INTO notes(message) VALUES ($1)', ['lost'], 0)
        self.assertEqual(self.accounts.sql(account, 'select', 'SELECT count(*) AS n FROM notes', []), [{'n': 0}])

    def test_password_required_import_and_attach_denied(self):
        with self.assertRaises(AccountError):
            self.accounts.register('no_password', '')
        with self.assertRaises(AccountError):
            self.accounts.register('short', '1234')
        source = Path(self.tmp.name) / 'import.db'
        with closing(sqlite3.connect(source)) as db:
            db.execute('CREATE TABLE profiles(id INTEGER PRIMARY KEY, name TEXT)')
            db.execute('INSERT INTO profiles(name) VALUES ($1)', {'1': 'Learner'})
            db.commit()
        account = self.accounts.session(self.accounts.register('imported', 'long-password-4', source.read_bytes()))[0]
        self.assertEqual(self.accounts.sql(account, 'select', 'SELECT name FROM profiles', []), [{'name': 'Learner'}])
        with self.assertRaises((AccountError, sqlite3.DatabaseError)):
            self.accounts.sql(account, 'execute', "ATTACH DATABASE '/tmp/other.sqlite3' AS other", [])


if __name__ == '__main__':
    unittest.main()
