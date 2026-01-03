import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from safe_share import AccessPolicy, make_handler, safe_resolve


class SafeShareTests(unittest.TestCase):
    def test_download_limit_is_atomic(self):
        policy = AccessPolicy("a" * 16, 60, 1)
        self.assertEqual(policy.available(), (True, "ok"))
        self.assertEqual(policy.available(), (True, "ok"))
        self.assertEqual(policy.reserve_download(), (True, "ok"))
        self.assertEqual(policy.reserve_download(), (False, "download limit reached"))

    def test_token_comparison(self):
        policy = AccessPolicy("correct-token-123", 60, 1)
        self.assertTrue(policy.valid_token("correct-token-123"))
        self.assertFalse(policy.valid_token("wrong-token-12345"))

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(safe_resolve(root, "../outside"))
            child = root / "inside.txt"
            child.write_text("ok", encoding="utf-8")
            self.assertEqual(safe_resolve(root, "inside.txt"), child.resolve())

    def test_http_download_obeys_token_and_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "release.txt"
            target.write_text("field-tested", encoding="utf-8")
            token = "correct-token-123"
            policy = AccessPolicy(token, 60, 1)
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(target, policy))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                with self.assertRaises(urllib.error.HTTPError) as missing:
                    urllib.request.urlopen(f"{base}/wrong-token-1234/release.txt", timeout=2)
                self.assertEqual(missing.exception.code, 404)
                with urllib.request.urlopen(f"{base}/{token}/release.txt", timeout=2) as response:
                    self.assertEqual(response.read(), b"field-tested")
                with self.assertRaises(urllib.error.HTTPError) as exhausted:
                    urllib.request.urlopen(f"{base}/{token}/release.txt", timeout=2)
                self.assertEqual(exhausted.exception.code, 410)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
