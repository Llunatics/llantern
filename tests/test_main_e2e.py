"""End-to-end CLI test: real main() through the FakeSocks5 + local HTTP.

Unlike test_cli.py (which mocks fetch), this proves the whole binary path:
arg parsing -> SOCKS5 handshake -> HTTP -> inspection -> table/JSON output.
"""
import http.server
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import llantern
from llantern import main
from test_fetch import FakeSocks5, Handler

BODY = (b"<html><head><title>Lentera Uji</title>"
        b'<meta name="description" content="Halaman uji."></head>'
        b'<body><h1>Halo</h1><a href="http://abc.onion/x">satu</a>'
        b'<a href="/dalam">dua</a></body></html>')


class E2EHandler(Handler):
    def do_GET(self):
        if self.path == "/":
            self._send(200, BODY)
        else:
            self._send(404, b"tak ada")


class TestMainE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), E2EHandler)
        cls.hport = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.socks = FakeSocks5()
        cls.socks.start()
        cls.proxy = "127.0.0.1:%d" % cls.socks.port

    def _url(self, path="/"):
        return "http://127.0.0.1:%d%s" % (self.hport, path)

    def test_table_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--proxy", self.proxy, "--timeout", "10",
                       self._url()])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Lentera Uji", out)   # title inspected
        self.assertIn("Halaman uji.", out)  # description
        self.assertIn("2 total", out)       # link count

    def test_json_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--proxy", self.proxy, "--timeout", "10",
                       "--json", self._url()])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["status"], 200)
        self.assertEqual(data["page"]["title"], "Lentera Uji")
        self.assertEqual(data["page"]["link_total"], 2)

    def test_404_exit_1(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--proxy", self.proxy, "--timeout", "10",
                       self._url("/hilang")])
        self.assertEqual(rc, 1)

    def test_save_html(self):
        with tempfile.TemporaryDirectory() as d:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["--proxy", self.proxy, "--timeout", "10",
                           "--save-html", d, self._url()])
            self.assertEqual(rc, 0)
            p = os.path.join(d, "page_01.html")
            self.assertTrue(os.path.exists(p))
            with open(p, "rb") as f:
                self.assertEqual(f.read(), BODY)

    def test_multiple_urls(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--proxy", self.proxy, "--timeout", "10",
                       self._url(), self._url("/hilang")])
        self.assertEqual(rc, 1)  # one failed
        self.assertIn("Lentera Uji", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
