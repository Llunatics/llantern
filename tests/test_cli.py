"""Unit test CLI llantern.main: exit code, --json, --file, --save-html.

fetch() di-mock penuh: ini menguji plumbing CLI, bukan jaringan.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import llantern
from llantern import LlantError, fmt_size, main

HTML = (b"<html><head><title>T</title></head>"
        b"<body><h1>Halo</h1><a href='http://x.onion/'>x</a></body></html>")


def _res(url="http://abc123.onion/", status=200):
    return {
        "url": url, "status": status, "reason": "OK",
        "headers": {"content-type": "text/html"}, "body": HTML,
        "elapsed": 0.5, "redirects": [], "is_onion": True,
    }


def _run(argv):
    with mock.patch.object(llantern, "fetch", return_value=_res()) as m:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(argv)
    return rc, out.getvalue(), err.getvalue(), m


class TestMain(unittest.TestCase):
    def test_teks_sukses_exit_0(self):
        rc, out, _, m = _run(["abc123.onion"])
        self.assertEqual(rc, 0)
        self.assertIn("llantern", out)
        self.assertIn("Halo", out)  # heading ikut dirender
        m.assert_called_once()
        # host dikirim apa adanya ke fetch (skema ditambah otomatis)
        self.assertIn("abc123.onion", m.call_args[0][0])

    def test_json_shape(self):
        rc, out, _, _ = _run(["abc123.onion", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["url"], "http://abc123.onion/")
        self.assertEqual(data["status"], 200)
        self.assertTrue(data["is_onion"])
        self.assertEqual(data["page"]["title"], "T")
        self.assertEqual(data["page"]["link_counts"]["onion"], 1)

    def test_status_404_exit_1(self):
        with mock.patch.object(llantern, "fetch",
                               return_value=_res(status=404)):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = main(["abc123.onion"])
        self.assertEqual(rc, 1)

    def test_fetch_error_lanjut_url_berikutnya(self):
        from llantern import FetchError
        with mock.patch.object(llantern, "fetch",
                               side_effect=[FetchError("mati"), _res()]):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = main(["satu.onion", "dua.onion"])
        self.assertEqual(rc, 1)  # satu gagal -> exit 1, tapi lanjut

    def test_proxy_mati_exit_2(self):
        with mock.patch.object(llantern, "fetch",
                               side_effect=LlantError("proxy mati")):
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["abc123.onion"])
        self.assertEqual(rc, 2)

    def test_file_dibaca_komentar_dilewati(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as f:
            f.write("# komentar\n\na.onion\nb.onion\n")
            path = f.name
        try:
            rc, _, _, m = _run(["--file", path])
            self.assertEqual(rc, 0)
            self.assertEqual(m.call_count, 2)
        finally:
            os.unlink(path)

    def test_file_tak_ada_llanterror(self):
        with self.assertRaises(LlantError):
            main(["--file", "/tidak/ada/sama-sekali.txt"])

    def test_save_html_menulis_file(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _, _, _ = _run(["abc123.onion", "--save-html", d])
            self.assertEqual(rc, 0)
            p = os.path.join(d, "page_01.html")
            self.assertTrue(os.path.exists(p))
            with open(p, "rb") as f:
                self.assertEqual(f.read(), HTML)

    def test_max_redirects_negatif_ditolak(self):
        with self.assertRaises(LlantError):
            main(["abc123.onion", "--max-redirects", "-1"])

    def test_timeout_nol_ditolak(self):
        with self.assertRaises(LlantError):
            main(["abc123.onion", "--timeout", "0"])

    def test_tanpa_url_argparse_exit_2(self):
        with self.assertRaises(SystemExit) as cm:
            with redirect_stderr(io.StringIO()):
                main([])
        self.assertEqual(cm.exception.code, 2)


class TestFmtSize(unittest.TestCase):
    def test_batas(self):
        self.assertEqual(fmt_size(0), "0 B")
        self.assertEqual(fmt_size(1023), "1023 B")
        self.assertEqual(fmt_size(1024), "1.0 KB")
        self.assertEqual(fmt_size(2_000_000), "1.9 MB")


if __name__ == "__main__":
    unittest.main()


class TestSigpipe(unittest.TestCase):
    def test_broken_pipe_no_traceback(self):
        import signal
        self.assertEqual(signal.getsignal(signal.SIGPIPE), signal.SIG_DFL)


class TestFileEncoding(unittest.TestCase):
    def test_non_utf8_file_no_traceback(self):
        import tempfile
        with tempfile.NamedTemporaryFile("wb", suffix=".txt",
                                         delete=False) as f:
            f.write(b"http://abc.onion/\xff\xfe\n# komen\n")
            path = f.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                # Proxy mati -> rc 2 dengan pesan galat bersih, BUKAN
                # traceback UnicodeDecodeError.
                rc = main(["--file", path, "--proxy", "127.0.0.1:1",
                           "--timeout", "1"])
            self.assertEqual(rc, 2)
            self.assertNotIn("Traceback", buf.getvalue())
        finally:
            os.unlink(path)
