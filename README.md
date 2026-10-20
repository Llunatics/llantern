# llantern

Lentera buat dark web — ambil halaman `.onion` lewat Tor, lalu bedah strukturnya: judul, heading, dan semua link yang dikelompokkan (hidden service lain / eksternal / internal).

**Stdlib-only**: tanpa dependensi pihak ketiga. Handshake SOCKS5 ditulis tangan di atas `socket` karena `urllib` tidak mendukung SOCKS.

## Fitur

- Fetch HTTP/HTTPS lewat proxy SOCKS5 Tor (default `127.0.0.1:9050`)
- Hostname dikirim mentah ke proxy (ATYP domain) — `.onion` **tidak** di-resolve via DNS lokal
- Ikuti redirect (maks. 5, bisa diatur; `--max-redirects 0` = kembalikan respons 3xx apa adanya), dukung `chunked` & `content-length`
- Bedah halaman: judul, meta description (fallback `og:description` / `twitter:description`), heading h1–h6, link, form, gambar, script, jumlah kata
- Klasifikasi link: `onion` (hidden service lain) · `external` · `internal` (termasuk `<a href="">`) · `anchor` · `mailto` · `other`
- Output laporan teks atau `--json`; opsi `--save-html` untuk arsip mentah
- 66 unit/integration test (termasuk SOCKS5 palsu + HTTP server lokal)
- Pengerasan: URL dengan CR/LF ditolak (anti request-smuggling), port tak
  valid / timeout / TLS gagal menjadi `FetchError` yang rapi (bukan
  traceback), batas 200 header, batas 5000 link & 2000 heading anti-DoS

## Syarat

- Python 3.8+
- Tor berjalan dengan SOCKS5 di `127.0.0.1:9050` (atau sesuaikan via `--proxy`)

```bash
tor &                                  # daemon Tor, sekali saja
llantern http://example.onion          # skema http:// boleh dihilangkan
```

Tanpa Tor, llantern berhenti dengan pesan yang jelas (exit code 2) — bukan traceback misterius.

## Penggunaan

```bash
# satu URL
python3 llantern.py example123.onion

# beberapa URL + output JSON
python3 llantern.py a1b2c3.onion d4e5f6.onion --json

# daftar target dari file
python3 llantern.py --file targets.txt --save-html ./dumps

# proxy Tor di host/port lain
python3 llantern.py example123.onion --proxy 127.0.0.1:9150
```

## Opsi

| Opsi | Default | Keterangan |
|---|---|---|
| `urls` | — | Satu/lebih URL `.onion` (atau clearnet); `http://` opsional |
| `--file FILE` | — | Daftar URL dari file (satu per baris, `#` = komentar) |
| `--proxy HOST:PORT` | `127.0.0.1:9050` | Proxy SOCKS5 Tor |
| `--timeout DETIK` | `30` | Timeout per koneksi |
| `--max-bytes N` | `2000000` | Batas ukuran body |
| `--max-redirects N` | `5` | Batas redirect berantai; `0` = jangan ikuti, kembalikan respons 3xx |
| `--user-agent UA` | `llantern/<versi>` | User-Agent kustom |
| `--json` | — | Keluarkan JSON, bukan laporan teks |
| `--save-html DIR` | — | Simpan HTML mentah tiap URL ke DIR |
| `--version` | — | Tampilkan versi |

## Contoh output

```
llantern — http://example123.onion/
  status   : 200 OK (1.24s, 48.2 KB, via 127.0.0.1:9050)
  judul    : Pasar Contoh
  deskripsi: Contoh hidden service.
  heading  :
    h1 Selamat datang
    h2 Katalog
  link     : 9 total — 1 onion · 2 external · 3 internal · 1 anchor · 1 mailto · 1 other
             · xyz789.onion (1)
             · example.com (2)
  struktur : 1 form · 2 gambar · 1 script · ~340 kata
```

## Skema JSON (`--json`)

```jsonc
{
  "url": "http://example123.onion/",
  "status": 200, "reason": "OK",
  "elapsed_s": 1.24, "bytes": 49374,
  "content_type": "text/html; charset=utf-8",
  "is_onion": true,
  "redirects": ["http://example123.onion/old"],
  "page": {                       // null jika bukan HTML / status != 200
    "title": "Pasar Contoh",
    "description": "Contoh hidden service.",
    "headings": [{"level": "h1", "text": "Selamat datang"}],
    "links": [{"url": "http://xyz789.onion/a", "text": "x", "class": "onion"}],
    "link_total": 6,
    "link_counts": {"onion": 1, "external": 2},
    "top_domains": [{"domain": "example.com", "count": 2}],
    "forms": 1, "images": 2, "scripts": 1, "words": 181
  }
}
```

## Klasifikasi link

| Kelas | Arti |
|---|---|
| `onion` | Hidden service **lain** — berguna untuk memetakan graf `.onion` |
| `external` | Situs clearnet lain |
| `internal` | Navigasi dalam situs yang sama (URL relatif / se-host) |
| `anchor` | Lompatan `#` dalam halaman |
| `mailto` / `other` | `mailto:` / skema lain (`javascript:`, …) |

## Cara kerja (ringkas)

| Lapisan | Implementasi |
|---|---|
| SOCKS5 | `socks5_connect()` — handshake no-auth RFC 1928 manual via `socket` |
| HTTP | Request `GET` + parser respons sendiri (status, header, chunked, content-length) |
| TLS | `.onion` → verifikasi sertifikat **mati** (identitas E2E sudah dijamin kriptografi Tor, seperti Tor Browser); clearnet → verifikasi CA penuh |
| HTML | `html.parser.HTMLParser` — tahan terhadap markup rusak; tag tak tertutup di-flush saat ringkasan dibuat |

## Exit code

| Kode | Arti |
|---|---|
| `0` | Semua URL berhasil (status < 400) |
| `1` | Sebagian/gagal fetch (URL dilewati, lanjut ke berikutnya) |
| `2` | Kesalahan konfigurasi: proxy mati, argumen salah, file tak terbaca |
| `130` | Dibatalkan (Ctrl-C) |

## Tes

```bash
python3 -m unittest discover -s tests -v
```

Suite memakai **SOCKS5 palsu + HTTP server lokal** (thread), jadi seluruh jalur — handshake, CONNECT, redirect, chunked, batas byte — teruji tanpa Tor asli dan tanpa jaringan luar.

## Struktur

```
llantern/
├── llantern.py   # seluruh tool (SOCKS5, HTTP, inspector, CLI)
├── tests/
│   ├── test_cli.py      # unit argumen CLI & exit code
│   ├── test_fetch.py    # integrasi via SOCKS5 palsu
│   ├── test_inspect.py  # unit PageInspector
│   └── test_main_e2e.py # e2e main() via server lokal
├── README.md
├── LICENSE
└── .gitignore
```

## Roadmap

- `--depth N`: crawl rekursif antar `.onion` dalam batas domain
- Deteksi bahasa & ekstraksi teks bersih (`--text`)
- Mode `robots.txt` untuk hidden service yang menyediakannya

## Lisensi

MIT — lihat [LICENSE](LICENSE).
