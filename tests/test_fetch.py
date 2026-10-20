"""Integration test lewat SOCKS5 palsu + HTTP server lokal (tanpa Tor asli).

FakeSocks5 menerima handshake no-auth, membaca CONNECT (ATYP domain),
lalu menjembatani byte ke HTTP server lokal. Ini membuktikan seluruh
jalur llantern — handshake, request, redirect, chunked — bekerja.
"""

import http.server
import io
import os
import select
import socket
import ssl
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llantern import (FetchError, LlantError, fetch, parse_proxy,
                      socks5_connect, tls_context)

BODY = b"<html><head><title>Uji</title></head><body><h1>Halo</h1></body></html>"
CHUNKED = (b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/":
            self._send(200, BODY)
        elif self.path == "/pindah":
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/loc200":
            self.send_response(200)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"done")
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(CHUNKED)
        elif self.path == "/gede":
            self.send_response(200)
            self.send_header("Content-Length", "99999999")
            self.end_headers()
        elif self.path == "/stall":
            # Kirim header lalu diam: memicu socket.timeout di sisi klien.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "100")
            self.end_headers()
            time.sleep(4)
        elif self.path == "/banjir-header":
            self.send_response(200)
            for i in range(300):
                self.send_header("X-Pad-%d" % i, "y" * 50)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/techunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Transfer-Encoding", "gzip, chunked")
            self.end_headers()
            self.wfile.write(CHUNKED)
        else:
            self._send(404, b"tak ada")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeSocks5(threading.Thread):
    """SOCKS5 no-auth palsu: CONNECT domain -> teruskan ke target beneran."""

    def __init__(self):
        super().__init__(daemon=True)
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(8)
        self.port = self.lsock.getsockname()[1]
        self.seen_host = None  # host domain yang diminta klien

    def run(self):
        while True:
            c, _ = self.lsock.accept()
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        try:
            if c.recv(3) != b"\x05\x01\x00":
                c.close()
                return
            c.sendall(b"\x05\x00")
            req = c.recv(4)
            atyp = req[3]
            if atyp == 0x03:
                ln = c.recv(1)[0]
                host = c.recv(ln).decode("idna")
            elif atyp == 0x01:
                host = socket.inet_ntoa(c.recv(4))
            else:
                c.close()
                return
            port = int.from_bytes(c.recv(2), "big")
            self.seen_host = host
            c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00")
            upstream = socket.create_connection((host, port), timeout=10)
            self._relay(c, upstream)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    @staticmethod
    def _relay(a, b):
        for s in (a, b):
            s.setblocking(False)
        pair = {a: b, b: a}
        try:
            while True:
                r, _, _ = select.select([a, b], [], [], 30)
                if not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    pair[s].sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass


class TestFetch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        cls.hport = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.socks = FakeSocks5()
        cls.socks.start()
        cls.proxy = ("127.0.0.1", cls.socks.port)

    def _fetch(self, path, **kw):
        base = dict(proxy=self.proxy, timeout=10, max_bytes=2_000_000,
                    max_redirects=5, user_agent="llantern-test")
        base.update(kw)
        return fetch("http://127.0.0.1:%d%s" % (self.hport, path), **base)

    def test_200_ok(self):
        r = self._fetch("/")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["body"], BODY)
        self.assertGreater(r["elapsed"], 0)

    def test_redirect_diikuti(self):
        r = self._fetch("/pindah")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["url"], "http://127.0.0.1:%d/" % self.hport)
        self.assertEqual(len(r["redirects"]), 1)

    def test_redirect_loop_ditangkap(self):
        with self.assertRaises(FetchError):
            self._fetch("/loop", max_redirects=3)

    def test_redirect_tidak_diikuti_bila_nol(self):
        # max_redirects=0: respons 3xx dikembalikan apa adanya, bukan error.
        r = self._fetch("/pindah", max_redirects=0)
        self.assertEqual(r["status"], 302)
        self.assertEqual(r["redirects"], [])

    def test_chunked_body(self):
        r = self._fetch("/chunked")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["body"], b"Wikipedia")

    def test_404_tetap_hasil_bukan_error(self):
        r = self._fetch("/hilang")
        self.assertEqual(r["status"], 404)

    def test_batas_max_bytes(self):
        with self.assertRaises(FetchError):
            self._fetch("/gede")

    def test_port_tidak_valid_jadi_fetch_error(self):
        # Dulu: ValueError mentah (traceback). Sekarang: FetchError yang rapi.
        with self.assertRaises(FetchError):
            fetch("http://127.0.0.1:abc/", proxy=self.proxy, timeout=10,
                  max_bytes=1000, max_redirects=5, user_agent="t")

    def test_url_crlf_ditolak(self):
        with self.assertRaises(FetchError):
            fetch("http://127.0.0.1:%d/a\r\nX: 1" % self.hport,
                  proxy=self.proxy, timeout=10, max_bytes=1000,
                  max_redirects=5, user_agent="t")
    def test_url_kontrol_lain_ditolak(self):
        # fuzz round 2: gate dulu hanya CR/LF; NUL/ESC/DEL juga ditolak
        for bad in ("\x00", "\x1b[2J", "\x7f", "\x07"):
            with self.assertRaises(FetchError, msg=repr(bad)):
                fetch("http://127.0.0.1:%d/a%sb" % (self.hport, bad),
                      proxy=self.proxy, timeout=10, max_bytes=1000,
                      max_redirects=5, user_agent="t")


    def test_timeout_jadi_fetch_error_bukan_traceback(self):
        with self.assertRaises(FetchError):
            self._fetch("/stall", timeout=1)

    def test_banjir_header_ditolak(self):
        with self.assertRaises(FetchError):
            self._fetch("/banjir-header")

    def test_transfer_encoding_gabung_tetap_dechunk(self):
        r = self._fetch("/techunked")
        self.assertEqual(r["body"], b"Wikipedia")

    def test_parse_proxy_ipv6_kurung(self):
        self.assertEqual(parse_proxy("[::1]:9050"), ("::1", 9050))
        self.assertEqual(parse_proxy("127.0.0.1:9050"), ("127.0.0.1", 9050))

    def test_domain_dikirim_mentah_ke_proxy(self):
        # .onion TIDAK boleh di-resolve lokal; proxy yang menerima hostname
        s = socks5_connect("127.0.0.1", self.socks.port,
                           "contoh123.onion", 80, timeout=10)
        s.close()
        # beri waktu thread proxy memproses
        for _ in range(50):
            if self.socks.seen_host == "contoh123.onion":
                break
            time.sleep(0.05)
        self.assertEqual(self.socks.seen_host, "contoh123.onion")

    def test_proxy_mati_pesan_ramah(self):
        with self.assertRaises(LlantError) as cm:
            fetch("http://x.onion/", proxy=("127.0.0.1", 1), timeout=2,
                  max_bytes=1000, max_redirects=5, user_agent="t")
        self.assertIn("tor", str(cm.exception).lower())

    def test_parse_proxy_salah(self):
        from llantern import LlantError as LE
        with self.assertRaises(LE):
            parse_proxy("tanpa-port")
        with self.assertRaises(LE):
            parse_proxy("host:bukanangka")

    def test_tls_onion_tanpa_verifikasi(self):
        # Keputusan keamanan inti: .onion -> verify MATI (identitas
        # dijamin kriptografi Tor), clearnet -> verify NYALA (CA penuh).
        ctx_onion = tls_context(True)
        self.assertEqual(ctx_onion.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx_onion.check_hostname)
        ctx_clear = tls_context(False)
        self.assertEqual(ctx_clear.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx_clear.check_hostname)


if __name__ == "__main__":
    unittest.main()


class _FakeSock:
    """Socket stub for socks5_connect unit tests (no real proxy)."""

    def __init__(self, replies):
        self._replies = list(replies)

    def sendall(self, data):
        pass

    def recv(self, n):
        return self._replies.pop(0) if self._replies else b""

    def close(self):
        pass


class TestRegressionDeep8(unittest.TestCase):
    """Regression guards from deep-8 mutation testing (2026-10-20)."""

    @classmethod
    def setUpClass(cls):
        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        cls.hport = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.socks = FakeSocks5()
        cls.socks.start()
        cls.proxy = ("127.0.0.1", cls.socks.port)

    def _fetch(self, path, **kw):
        base = dict(proxy=self.proxy, timeout=10, max_bytes=2_000_000,
                    max_redirects=5, user_agent="llantern-test")
        base.update(kw)
        return fetch("http://127.0.0.1:%d%s" % (self.hport, path), **base)

    # L01: a proxy that selects an auth method (0x02) must be refused.
    def test_proxy_demanding_auth_rejected(self):
        from unittest import mock
        fake = _FakeSock([b"\x05\x02"])
        with mock.patch("llantern.socket.create_connection", return_value=fake):
            with self.assertRaises(LlantError) as cm:
                socks5_connect("127.0.0.1", 9999, "contoh.onion", 80, timeout=5)
        self.assertIn("handshake", str(cm.exception))

    # L02: hostnames longer than 255 bytes cannot fit the SOCKS5 length byte.
    def test_hostname_over_255_bytes_rejected(self):
        from unittest import mock
        fake = _FakeSock([b"\x05\x00"])
        with mock.patch("llantern.socket.create_connection", return_value=fake):
            with self.assertRaises(FetchError) as cm:
                socks5_connect("127.0.0.1", 9999,
                               ".".join(["a" * 60] * 5), 80, timeout=5)
        self.assertIn("terlalu panjang", str(cm.exception))

    # L06: chunked bodies are capped by max_bytes too.
    def test_chunked_body_over_max_bytes_rejected(self):
        from llantern import _read_response
        data = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n")
        with self.assertRaises(FetchError) as cm:
            _read_response(io.BytesIO(data), 8)
        self.assertIn("melebihi batas", str(cm.exception))

    # L07: an over-limit Content-Length is rejected up front (the
    # content-length read loop itself has no size check).
    def test_content_length_over_max_bytes_rejected_upfront(self):
        from llantern import _read_response
        data = b"HTTP/1.1 200 OK\r\nContent-Length: 15000000\r\n\r\n"
        with self.assertRaises(FetchError) as cm:
            _read_response(io.BytesIO(data), 2_000_000)
        self.assertIn("melebihi batas", str(cm.exception))

    # L09: a self-redirect is a loop, reported as such.
    def test_redirect_loop_reported_as_loop(self):
        with self.assertRaises(FetchError) as cm:
            self._fetch("/loop", max_redirects=10)
        self.assertIn("berputar", str(cm.exception))

    # L10: a 200 response carrying a Location header is NOT a redirect.
    def test_200_with_location_header_not_followed(self):
        r = self._fetch("/loc200")
        self.assertEqual(r["status"], 200)
        self.assertTrue(r["url"].endswith("/loc200"))
