"""Request guard checks for the experimental web server."""
import json
import sys
import threading
import unittest
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.modules.setdefault('faster_whisper', SimpleNamespace(WhisperModel=object))
from server import App, LimitedServer, MAX_BODY  # noqa: E402


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.server = LimitedServer(('127.0.0.1', 0), App)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, path, data=None, headers=None):
        address = f'127.0.0.1:{self.server.server_port}'
        request = Request(f'http://{address}{path}', data=data, headers=headers or {})
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, response.read()
        except HTTPError as error:
            try:
                return error.code, error.read()
            finally:
                error.close()

    def test_origin_and_json_guards(self):
        address = f'127.0.0.1:{self.server.server_port}'
        self.assertEqual(self.call('/health')[0], 200)
        self.assertEqual(self.call('/ollama/api/chat', b'{}', {'Origin': 'https://evil.example', 'Content-Type': 'application/json'})[0], 403)
        self.assertEqual(self.call('/ollama/api/chat', b'{}', {'Origin': f'https://{address}', 'Content-Type': 'text/plain'})[0], 415)
        self.assertEqual(self.call('/ollama/api/chat', json.dumps({'model': 'wrong'}).encode(), {'Origin': f'https://{address}', 'Content-Type': 'application/json'})[0], 403)
        self.assertEqual(self.call('/transcribe?lang=fr', b'1234', {'Origin': f'https://{address}'})[0], 400)

    def test_large_body_is_rejected_before_read(self):
        address = f'127.0.0.1:{self.server.server_port}'
        status, body = self.call('/transcribe', b'x', {'Origin': f'https://{address}', 'Content-Length': str(MAX_BODY + 1)})
        self.assertEqual(status, 400)
        self.assertIn(b'Request body too large', body)


if __name__ == '__main__':
    unittest.main()
