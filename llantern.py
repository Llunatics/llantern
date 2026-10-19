#!/usr/bin/env python3
"""
llantern — lentera buat dark web.

Fetch halaman .onion (atau clearnet) lewat proxy SOCKS5 Tor, lalu bedah
strukturnya: judul, deskripsi, heading, semua link (dikelompokkan
onion/eksternal/internal), form, gambar, dan statistik teks.

Stdlib-only: tanpa dependensi pihak ketiga. Handshake SOCKS5 ditulis
tangan di atas modul `socket` karena urllib tidak mendukung SOCKS.

Contoh:
    llantern http://example.onion
    llantern example.onion --json
    llantern --file targets.txt --save-html ./dumps
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
from html.parser import HTMLParser

VERSION = "1.0.0"
DEFAULT_PROXY = "127.0.0.1:9050"
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_BYTES = 2_000_000
DEFAULT_MAX_REDIRECTS = 5
USER_AGENT = "llantern/%s (+https://github.com/Llunatics/llantern)" % VERSION


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

class LlantError(Exception):
    """Kesalahan fatal llantern (config, proxy mati, argumen salah)."""


class FetchError(Exception):
    """Gagal mengambil satu URL (tetap lanjut ke URL berikutnya)."""


# ---------------------------------------------------------------------------
# SOCKS5 (RFC 1928) — koneksi TCP mentah ke proxy, tanpa auth
# ---------------------------------------------------------------------------

def socks5_connect(proxy_host, proxy_port, dest_host, dest_port, timeout):
    """Buka tunnel TCP ke dest_host:dest_port lewat proxy SOCKS5.

    dest_host dikirim sebagai nama domain (ATYP=0x03) supaya TIDAK
    di-resolve secara lokal — wajib untuk .onion yang memang tidak
    ada di DNS biasa.
    """
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except OSError as e:
        raise LlantError(
            "proxy SOCKS5 %s:%d tidak bisa dihubungi (%s).\n"
            "Tor tampaknya belum jalan — nyalakan dulu dengan perintah `tor`,\n"
            "atau arahkan ke proxy lain via --proxy HOST:PORT."
            % (proxy_host, proxy_port, e.strerror or e)
        )
    try:
        # sapaan: VER=5, 1 metode, NO AUTH (0x00)
        sock.sendall(b"\x05\x01\x00")
        resp = _recvn(sock, 2)
        if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
            raise LlantError("proxy %s:%d menolak handshake SOCKS5 (no-auth)"
                             % (proxy_host, proxy_port))
        # permintaan CONNECT, alamat sebagai domain agar proxy yang resolve
        try:
            host_b = dest_host.encode("idna")
        except (UnicodeError, ValueError):
            raise FetchError("nama host tidak valid: %s" % dest_host)
        if len(host_b) > 255:
            raise FetchError("nama host terlalu panjang: %s" % dest_host)
        req = (b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b
               + dest_port.to_bytes(2, "big"))
        sock.sendall(req)
        rep = _recvn(sock, 4)
        if len(rep) < 4 or rep[0] != 0x05:
            raise LlantError("balasan SOCKS5 rusak dari %s:%d"
                             % (proxy_host, proxy_port))
        if rep[1] != 0x00:
            raise FetchError("SOCKS5 CONNECT ke %s:%d ditolak (kode 0x%02x)"
                             % (dest_host, dest_port, rep[1]))
        # buang sisa alamat bind sesuai ATYP
        atyp = rep[3]
        if atyp == 0x01:
            _recvn(sock, 4 + 2)
        elif atyp == 0x04:
            _recvn(sock, 16 + 2)
        elif atyp == 0x03:
            ln = _recvn(sock, 1)
            _recvn(sock, (ln[0] if ln else 0) + 2)
        return sock
    except (LlantError, FetchError):
        sock.close()
        raise
    except OSError as e:
        sock.close()
        raise FetchError("I/O proxy saat handshake: %s" % e)


def _recvn(sock, n):
    """Baca tepat n byte (atau kurang bila koneksi putus)."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# HTTP minimal di atas tunnel SOCKS5
# ---------------------------------------------------------------------------

REDIRECTS = {301, 302, 303, 307, 308}


def tls_context(is_onion):
    """Konteks TLS untuk koneksi lewat Tor.

    Host .onion: verifikasi sertifikat dimatikan — identitas dan
    enkripsi end-to-end sudah dijamin kriptografi onion service
    itu sendiri (Tor Browser memperlakukan .onion sebagai secure
    context dengan alasan yang sama).
    Host clearnet: verifikasi CA penuh seperti biasa.
    """
    ctx = ssl.create_default_context()
    if is_onion:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _read_response(fp, max_bytes):
    """Baca status line, header, dan body (chunked / content-length / EOF)."""
    status_line = fp.readline(8192).decode("iso-8859-1").strip()
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise FetchError("status line HTTP tidak valid: %r" % status_line[:60])
    status = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ""

    headers = {}
    # Batas jumlah header: server jahat bisa streaming header tanpa akhir
    # (max_bytes hanya membatasi body).
    for _ in range(200):
        line = fp.readline(8192).decode("iso-8859-1")
        if line in ("\r\n", "\n", ""):
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    else:
        raise FetchError("terlalu banyak header HTTP (>200)")

    body = b""
    # Transfer-Encoding bisa berupa daftar ("gzip, chunked"): yang penting
    # ada token chunked di dalamnya.
    if "chunked" in headers.get("transfer-encoding", "").lower():
        while True:
            size_line = fp.readline(256).decode("iso-8859-1").strip()
            try:
                size = int(size_line.split(";")[0], 16)
            except ValueError:
                raise FetchError("chunked encoding rusak")
            if size == 0:
                fp.readline(256)  # CRLF penutup + trailer diabaikan
                break
            while size > 0:
                want = min(size, 65536)
                chunk = fp.read(want)
                if not chunk:
                    raise FetchError("body chunked terpotong")
                if len(body) + len(chunk) > max_bytes:
                    raise FetchError("body melebihi batas %d byte" % max_bytes)
                body += chunk
                size -= len(chunk)
            fp.readline(256)  # CRLF akhir chunk
    elif headers.get("content-length", "").isdigit():
        remaining = int(headers["content-length"])
        if remaining > max_bytes:
            raise FetchError("content-length %d melebihi batas %d byte"
                             % (remaining, max_bytes))
        while remaining > 0:
            chunk = fp.read(min(remaining, 65536))
            if not chunk:
                raise FetchError("body terpotong (%d byte hilang)" % remaining)
            body += chunk
            remaining -= len(chunk)
    else:
        while True:
            chunk = fp.read(65536)
            if not chunk:
                break
            if len(body) + len(chunk) > max_bytes:
                raise FetchError("body melebihi batas %d byte" % max_bytes)
            body += chunk
    return status, reason, headers, body


def fetch(url, proxy, timeout, max_bytes, max_redirects, user_agent):
    """Ambil satu URL lewat proxy SOCKS5. Kembalikan dict hasil.

    Mengikuti redirect (maks. max_redirects). Untuk host .onion,
    verifikasi sertifikat TLS dinonaktifkan — identitas .onion sudah
    dijamin kriptografi Tor itu sendiri (seperti Tor Browser).
    """
    if "://" not in url:
        url = "http://" + url
    visited = []
    for _ in range(max_redirects + 1):
        if "\r" in url or "\n" in url:
            # Jangan biarkan CR/LF lolos ke request line mentah (request
            # smuggling via argumen CLI yang jahat / Location redirect).
            raise FetchError("URL mengandung karakter kontrol: %r" % url[:80])
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise FetchError("skema tidak didukung: %s" % parsed.scheme)
        host = parsed.hostname or ""
        if not host:
            raise FetchError("URL tanpa host: %s" % url)
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            raise FetchError("port tidak valid: %s" % url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        is_onion = host.lower().endswith(".onion")

        sock = socks5_connect(proxy[0], proxy[1], host, port, timeout)
        try:
            sock.settimeout(timeout)
            try:
                if parsed.scheme == "https":
                    ctx = tls_context(is_onion)
                    sock = ctx.wrap_socket(sock, server_hostname=host)
            except OSError as e:
                raise FetchError("TLS gagal ke %s: %s" % (host, e))
            req = (
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml\r\n"
                "Accept-Language: en-US,en;q=0.9\r\n"
                "Connection: close\r\n\r\n"
            ) % (path, host, user_agent)
            t0 = time.monotonic()
            try:
                sock.sendall(req.encode("ascii", "ignore"))
                fp = sock.makefile("rb")
                try:
                    status, reason, headers, body = _read_response(fp, max_bytes)
                finally:
                    fp.close()
            except OSError as e:
                # Termasuk socket.timeout: server lambat/mati -> FetchError,
                # bukan traceback mentah.
                raise FetchError("I/O saat mengambil %s: %s" % (host, e))
            elapsed = time.monotonic() - t0
        finally:
            try:
                sock.close()
            except OSError:
                pass

        visited.append(url)
        if status in REDIRECTS and headers.get("location"):
            url = urllib.parse.urljoin(url, headers["location"])
            if url in visited:
                raise FetchError("redirect berputar: %s" % url)
            continue
        return {
            "url": url,
            "status": status,
            "reason": reason,
            "headers": headers,
            "body": body,
            "elapsed": elapsed,
            "redirects": visited[:-1],
            "is_onion": is_onion,
        }
    raise FetchError("terlalu banyak redirect (>%d)" % max_redirects)


# ---------------------------------------------------------------------------
# pemeriksa struktur halaman
# ---------------------------------------------------------------------------

class PageInspector(HTMLParser):
    # Batas agar halaman jahat (jutaan link/heading) tidak menghabiskan RAM.
    MAX_LINKS = 5000
    MAX_HEADINGS = 2000

    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.title = ""
        self._in_title = False
        self.description = ""
        self.headings = []          # [(level, teks)]
        self._cur_heading = None
        self.links = []             # [(href_abs, teks, kelas)]
        self._cur_link = None
        self.forms = 0
        self.images = 0
        self.scripts = 0
        self._words = 0
        self._in_script_style = False

    # -- util --
    @staticmethod
    def _classify(href, base):
        """Kelompokkan link:
        - onion    : hidden service LAIN (menarik untuk pemetaan graf .onion)
        - external : situs clearnet lain
        - internal : navigasi dalam situs yang sama (relatif / se-host)
        - anchor   : lompatan # dalam halaman
        - mailto / other
        """
        absu = urllib.parse.urljoin(base, href)
        p = urllib.parse.urlparse(absu)
        host = (p.hostname or "").lower()
        base_host = (urllib.parse.urlparse(base).hostname or "").lower()
        if href.startswith("#"):
            return absu, "anchor"
        if p.scheme in ("http", "https"):
            if host == base_host:
                return absu, "internal"
            if host.endswith(".onion"):
                return absu, "onion"
            return absu, "external"
        if p.scheme == "mailto":
            return absu, "mailto"
        return absu, "other"

    # -- parser hooks --
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "meta" and a.get("name", "").lower() == "description":
            self.description = a.get("content", "").strip()[:300]
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._cur_heading = [tag, ""]
        elif tag == "a" and a.get("href"):
            absu, cls = self._classify(a["href"].strip(), self.base)
            self._cur_link = [absu, "", cls]
        elif tag == "form":
            self.forms += 1
        elif tag == "img":
            self.images += 1
        elif tag == "script":
            self.scripts += 1
            self._in_script_style = True
        elif tag == "style":
            self._in_script_style = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6") and self._cur_heading:
            lvl, txt = self._cur_heading
            txt = " ".join(txt.split())
            if txt and len(self.headings) < self.MAX_HEADINGS:
                self.headings.append((lvl, txt[:160]))
            self._cur_heading = None
        elif tag == "a" and self._cur_link:
            absu, txt, cls = self._cur_link
            txt = " ".join(txt.split())
            if len(self.links) < self.MAX_LINKS:
                self.links.append((absu, txt[:120], cls))
            self._cur_link = None
        elif tag in ("script", "style"):
            self._in_script_style = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._cur_heading is not None:
            self._cur_heading[1] += data
        if self._cur_link is not None:
            self._cur_link[1] += data
        if not self._in_script_style:
            self._words += len(data.split())

    def summary(self):
        self.title = " ".join(self.title.split())[:200]
        # flush tag yang tidak pernah ditutup (HTML rusak / EOF tiba-tiba)
        if self._cur_link:
            absu, txt, cls = self._cur_link
            txt = " ".join(txt.split())
            if len(self.links) < self.MAX_LINKS:
                self.links.append((absu, txt[:120], cls))
            self._cur_link = None
        if self._cur_heading:
            lvl, txt = self._cur_heading
            txt = " ".join(txt.split())
            if txt and len(self.headings) < self.MAX_HEADINGS:
                self.headings.append((lvl, txt[:160]))
            self._cur_heading = None
        by_class = {}
        for _, _, cls in self.links:
            by_class[cls] = by_class.get(cls, 0) + 1
        domains = {}
        for absu, _, cls in self.links:
            if cls in ("onion", "external"):
                h = urllib.parse.urlparse(absu).hostname or "?"
                domains[h] = domains.get(h, 0) + 1
        top_domains = sorted(domains.items(), key=lambda kv: kv[1], reverse=True)[:8]
        return {
            "title": self.title,
            "description": self.description,
            "headings": [{"level": l, "text": t} for l, t in self.headings],
            "link_counts": by_class,
            "link_total": len(self.links),
            "links": [{"url": u, "text": t, "class": c}
                      for u, t, c in self.links[:200]],
            "top_domains": [{"domain": d, "count": n} for d, n in top_domains],
            "forms": self.forms,
            "images": self.images,
            "scripts": self.scripts,
            "words": self._words,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_proxy(s):
    if ":" not in s:
        raise LlantError("--proxy harus HOST:PORT, dapat: %s" % s)
    host, port = s.rsplit(":", 1)
    if not port.isdigit():
        raise LlantError("port proxy bukan angka: %s" % s)
    # Terima IPv6 dalam kurung: [::1]:9050
    if len(host) > 2 and host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, int(port)


def fmt_size(n):
    if n < 1024:
        return "%d B" % n
    if n < 1024 * 1024:
        return "%.1f KB" % (n / 1024)
    return "%.1f MB" % (n / 1024 / 1024)


def report_text(res, insp, proxy_str):
    L = []
    L.append("llantern — %s" % res["url"])
    L.append("  status   : %d %s (%.2fs, %s, via %s)"
             % (res["status"], res["reason"], res["elapsed"],
                fmt_size(len(res["body"])), proxy_str))
    if res["redirects"]:
        L.append("  redirect : %d hop" % len(res["redirects"]))
    if insp["title"]:
        L.append("  judul    : %s" % insp["title"])
    if insp["description"]:
        L.append("  deskripsi: %s" % insp["description"])
    if insp["headings"]:
        L.append("  heading  :")
        for h in insp["headings"][:12]:
            L.append("    %s %s" % (h["level"], h["text"]))
        if len(insp["headings"]) > 12:
            L.append("    … +%d lagi" % (len(insp["headings"]) - 12))
    lc = insp["link_counts"]
    L.append("  link     : %d total — %s"
             % (insp["link_total"],
                " · ".join("%d %s" % (lc[k], k) for k in
                            ("onion", "external", "internal",
                             "anchor", "mailto", "other") if k in lc)
                or "tidak ada"))
    for d in insp["top_domains"][:5]:
        L.append("             · %s (%d)" % (d["domain"], d["count"]))
    L.append("  struktur : %d form · %d gambar · %d script · ~%d kata"
             % (insp["forms"], insp["images"], insp["scripts"], insp["words"]))
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="llantern",
        description="Lentera buat dark web — ambil & bedah halaman .onion "
                    "lewat Tor (stdlib-only).")
    ap.add_argument("urls", nargs="*", help=".onion URL (skema http:// opsional)")
    ap.add_argument("--file", metavar="FILE",
                    help="baca daftar URL dari file (satu per baris, # = komentar)")
    ap.add_argument("--proxy", default=DEFAULT_PROXY, metavar="HOST:PORT",
                    help="proxy SOCKS5 Tor (default %(default)s)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="timeout detik per koneksi (default %(default)s)")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                    help="batas ukuran body (default %(default)s)")
    ap.add_argument("--max-redirects", type=int, default=DEFAULT_MAX_REDIRECTS,
                    help="batas redirect (default %(default)s)")
    ap.add_argument("--user-agent", default=USER_AGENT,
                    help="User-Agent kustom")
    ap.add_argument("--json", action="store_true",
                    help="keluarkan JSON, bukan laporan teks")
    ap.add_argument("--save-html", metavar="DIR",
                    help="simpan HTML mentah tiap URL ke DIR")
    ap.add_argument("--version", action="version", version="llantern " + VERSION)
    args = ap.parse_args(argv)

    if args.timeout <= 0:
        raise LlantError("--timeout harus positif")
    if args.max_bytes <= 0:
        raise LlantError("--max-bytes harus positif")
    if args.max_redirects < 0:
        raise LlantError("--max-redirects tidak boleh negatif")
    proxy = parse_proxy(args.proxy)

    urls = list(args.urls)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append(line)
        except OSError as e:
            raise LlantError("tidak bisa baca --file: %s" % e)
    if not urls:
        ap.error("butuh minimal satu URL (atau --file)")

    if args.save_html:
        os.makedirs(args.save_html, exist_ok=True)

    failed = 0
    for i, url in enumerate(urls):
        try:
            res = fetch(url, proxy, args.timeout, args.max_bytes,
                        args.max_redirects, args.user_agent)
        except (FetchError, LlantError) as e:
            # LlantError di sini = proxy mati di tengah jalan; hentikan semua
            print("✗ %s\n  galat: %s" % (url, e), file=sys.stderr)
            if isinstance(e, LlantError):
                return 2
            failed += 1
            continue

        ctype = res["headers"].get("content-type", "")
        page = None
        if res["status"] == 200 and "html" in ctype.lower():
            try:
                html = res["body"].decode("utf-8", errors="replace")
            except Exception:
                html = ""
            insp = PageInspector(res["url"])
            try:
                insp.feed(html)
            except Exception as e:  # parser defensif: jangan mati di HTML rusak
                print("  peringatan: parser HTML tersendat (%s)" % e,
                      file=sys.stderr)
            page = insp.summary()
            if args.save_html:
                fname = "page_%02d.html" % (i + 1)
                with open(os.path.join(args.save_html, fname),
                          "w", encoding="utf-8") as f:
                    f.write(html)

        if args.json:
            out = {
                "url": res["url"],
                "status": res["status"],
                "reason": res["reason"],
                "elapsed_s": round(res["elapsed"], 2),
                "bytes": len(res["body"]),
                "content_type": ctype,
                "redirects": res["redirects"],
                "is_onion": res["is_onion"],
                "page": page,
            }
            print(json.dumps(out, ensure_ascii=False))
        else:
            if page:
                print(report_text(res, page, args.proxy))
            else:
                print("llantern — %s\n  status: %d %s (%s, %s) — bukan HTML, isi dilewati"
                      % (res["url"], res["status"], res["reason"],
                         ctype or "content-type tak dikenal",
                         fmt_size(len(res["body"]))))
            if i < len(urls) - 1:
                print()
        if res["status"] >= 400:
            failed += 1

    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LlantError as e:
        print("llantern: %s" % e, file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\ndibatalkan.", file=sys.stderr)
        sys.exit(130)
