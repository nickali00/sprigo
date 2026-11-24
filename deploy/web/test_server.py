"""HTTP guards for the optional account server."""
import atexit
import base64
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

_test_data = tempfile.TemporaryDirectory()
atexit.register(_test_data.cleanup)
os.environ['DATA_DIR'] = _test_data.name
os.environ['SPRIGO_ACCESS_PASSWORD'] = 'test-only-access-password-12345'
os.environ['SPRIGO_SETUP_SECRET'] = 'test-only-operator-setup-secret-12345'
sys.modules.setdefault('faster_whisper', SimpleNamespace(WhisperModel=object))
from server import App, LimitedServer, MAX_BODY, ATTEMPTS, ATTEMPTS_LOCK  # noqa: E402

AUTH = 'Basic ' + base64.b64encode(b'sprigo:test-only-access-password-12345').decode()


class ServerTests(unittest.TestCase):
    def setUp(self):
        with ATTEMPTS_LOCK:
            ATTEMPTS.clear()
        self.server = LimitedServer(('127.0.0.1', 0), App)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.origin = f'https://127.0.0.1:{self.server.server_port}'

    def call(self, path, data=None, headers=None, auth=True):
        request_headers = dict(headers or {})
        if auth:
            request_headers['Authorization'] = AUTH
        request = Request(f'http://127.0.0.1:{self.server.server_port}{path}', data=data, headers=request_headers)
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, response.read(), response.headers
        except HTTPError as error:
            try:
                return error.code, error.read(), error.headers
            finally:
                error.close()

    def post(self, path, payload, extra=None, auth=True):
        headers = {'Origin': self.origin, 'Content-Type': 'application/json', 'X-Sprigo': '1', **(extra or {})}
        return self.call(path, json.dumps(payload).encode(), headers, auth)

    def test_access_origin_json_and_body_limits(self):
        self.assertEqual(self.call('/health', auth=False)[0], 200)
        self.assertEqual(self.call('/web-config')[0], 200)
        self.assertEqual(self.call('/', auth=False)[0], 401)
        self.assertEqual(self.post('/ollama/api/chat', {}, auth=False)[0], 401)
        self.assertEqual(self.post('/ollama/api/chat', {}, {'Origin': 'https://evil.example'})[0], 403)
        self.assertEqual(self.call('/ollama/api/chat', b'{}', {'Origin': self.origin, 'Content-Type': 'text/plain'})[0], 415)
        self.assertEqual(self.post('/ollama/api/chat', {'model': 'wrong'})[0], 403)
        self.assertEqual(self.call('/transcribe?lang=fr', b'1234', {'Origin': self.origin})[0], 400)
        status, body, _ = self.call('/transcribe', b'x', {'Origin': self.origin, 'Content-Length': str(MAX_BODY + 1)})
        self.assertEqual(status, 400)
        self.assertIn(b'Request body too large', body)

    def test_account_session_and_sql_placeholders(self):
        status, _, headers = self.post('/account/register', {'username': 'testuser', 'password': 'long-test-password', 'setupSecret': os.environ['SPRIGO_SETUP_SECRET']})
        self.assertEqual(status, 201)
        cookie = headers['Set-Cookie'].split(';', 1)[0]
        self.assertEqual(self.post('/account/sql', {'kind': 'select', 'sql': 'SELECT $1 AS value', 'args': [42]}, {'Cookie': cookie})[:2], (200, b'[{"value": 42}]'))
        self.assertEqual(self.post('/account/sql', {'kind': 'execute', 'sql': 'CREATE TABLE notes(message TEXT)', 'args': [], 'revision': 0}, {'Cookie': cookie})[0], 200)
        self.assertEqual(self.post('/account/sql', {'kind': 'execute', 'sql': 'INSERT INTO notes(message) VALUES ($1)', 'args': ['lost'], 'revision': 0}, {'Cookie': cookie})[0], 409)
        self.assertEqual(self.post('/account/logout', {}, {'Cookie': cookie})[0], 200)
        self.assertEqual(self.post('/account/sql', {'kind': 'select', 'sql': 'SELECT 1', 'args': []}, {'Cookie': cookie})[0], 401)
        self.assertEqual(self.post('/account/login', {'username': 'testuser', 'password': ''})[0], 401)

    def test_registration_requires_operator_secret(self):
        payload = {'username': 'newuser', 'password': 'long-test-password'}
        self.assertEqual(self.post('/account/register', payload)[0], 403)
        self.assertEqual(self.post('/account/register', {**payload, 'setupSecret': 'wrong'})[0], 403)
        self.assertEqual(self.post('/account/register', {**payload, 'setupSecret': os.environ['SPRIGO_SETUP_SECRET']})[0], 201)

    def test_registration_disabled_without_setup_secret(self):
        with patch('server.SETUP_SECRET', ''):
            self.assertEqual(self.post('/account/register', {
                'username': 'locked', 'password': 'long-test-password', 'setupSecret': os.environ['SPRIGO_SETUP_SECRET'],
            })[0], 403)


if __name__ == '__main__':
    unittest.main()
