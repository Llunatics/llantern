"""Unit test PageInspector: judul, heading, klasifikasi link, statistik."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llantern import PageInspector

SAMPLE = """<!doctype html><html><head>
<title>  Pasar Gelap  Demo </title>
<meta name="description" content="Contoh hidden service.">
</head><body>
<h1>Selamat datang</h1>
<h2>Katalog</h2><h2>Kontak</h2>
<p>Halo dunia, ini contoh teks.</p>
<a href="http://abc123.onion/barang">Barang A</a>
<a href="http://xyz789.onion/lain">Hidden service lain</a>
<a href="https://example.com/luar">Luar</a>
<a href="http://example.com/luar2">Luar2</a>
<a href="/internal/halaman">Internal</a>
<a href="relatif/lain">Relatif</a>
<a href="#fragmen">Loncat</a>
<a href="mailto:admin@abc123.onion">Email</a>
<a href="javascript:void(0)">JS</a>
<form action="/cari"><input name="q"></form>
<img src="a.png"><img src="b.png">
<script src="x.js"></script>
</body></html>"""


class TestInspector(unittest.TestCase):
    def setUp(self):
        self.insp = PageInspector("http://abc123.onion/")
        self.insp.feed(SAMPLE)
        self.s = self.insp.summary()

    def test_title_dinormalisasi(self):
        self.assertEqual(self.s["title"], "Pasar Gelap Demo")

    def test_description(self):
        self.assertEqual(self.s["description"], "Contoh hidden service.")

    def test_headings(self):
        self.assertEqual(
            self.s["headings"],
            [{"level": "h1", "text": "Selamat datang"},
             {"level": "h2", "text": "Katalog"},
             {"level": "h2", "text": "Kontak"}])

    def test_klasifikasi_link(self):
        by = {}
        for l in self.s["links"]:
            by.setdefault(l["class"], []).append(l["url"])
        self.assertEqual(by["onion"], ["http://xyz789.onion/lain"])
        self.assertEqual(len(by["external"]), 2)
        self.assertEqual(len(by["internal"]), 3)  # se-host + /internal + relatif
        self.assertEqual(len(by["anchor"]), 1)
        self.assertEqual(len(by["mailto"]), 1)
        self.assertEqual(len(by["other"]), 1)     # javascript:
        self.assertEqual(self.s["link_total"], 9)

    def test_link_counts(self):
        self.assertEqual(self.s["link_counts"]["onion"], 1)
        self.assertEqual(self.s["link_counts"]["external"], 2)

    def test_top_domains(self):
        doms = {d["domain"]: d["count"] for d in self.s["top_domains"]}
        self.assertEqual(doms.get("xyz789.onion"), 1)
        self.assertEqual(doms.get("example.com"), 2)
        self.assertNotIn("abc123.onion", doms)  # host sendiri = internal

    def test_struktur(self):
        self.assertEqual(self.s["forms"], 1)
        self.assertEqual(self.s["images"], 2)
        self.assertEqual(self.s["scripts"], 1)

    def test_words_mengabaikan_script(self):
        # kata di <script>/<style> tidak dihitung; teks body dihitung
        self.assertGreater(self.s["words"], 5)

    def test_html_rusak_tidak_meledak(self):
        insp = PageInspector("http://x.onion/")
        insp.feed("<html><h1>tanpa tutup<a href=/x>link")
        s = insp.summary()
        self.assertEqual(s["link_total"], 1)

    def test_relative_url_diresolve_ke_base(self):
        insp = PageInspector("http://abc123.onion/sub/dir/")
        insp.feed('<a href="../naik">x</a>')
        self.assertEqual(insp.summary()["links"][0]["url"],
                         "http://abc123.onion/sub/naik")


if __name__ == "__main__":
    unittest.main()


class TestBatas(unittest.TestCase):
    def test_link_dibatasi(self):
        insp = PageInspector("http://x.onion/")
        insp.feed("<a href='/a'>x</a>" * (PageInspector.MAX_LINKS + 100))
        self.assertEqual(insp.summary()["link_total"], PageInspector.MAX_LINKS)

    def test_heading_dibatasi(self):
        insp = PageInspector("http://x.onion/")
        insp.feed("<h1>t</h1>" * (PageInspector.MAX_HEADINGS + 100))
        self.assertEqual(len(insp.summary()["headings"]),
                         PageInspector.MAX_HEADINGS)


class TestFuzzParser(unittest.TestCase):
    def test_sampah_tidak_meledak(self):
        import random
        random.seed(42)
        pieces = ["<a href=", "<h1>", "</", "<title>", "<script>",
                  "http://x.onion/", '"', "'", ">", "\x00", "&amp;",
                  "<!--", "<!DOCTYPE", "<meta", "="]
        for _ in range(300):
            s = "".join(random.choice(pieces)
                        for _ in range(random.randint(1, 40)))
            insp = PageInspector("http://x.onion/")
            try:
                insp.feed(s)
                insp.summary()
            except Exception as e:
                self.fail("parser meledak pada %r: %s" % (s[:60], e))


class TestRegressionDeep8Inspect(unittest.TestCase):
    """Regression guards from deep-8 mutation testing (2026-10-20)."""

    # L13: script/style text must not inflate the word count.
    def test_script_and_style_words_not_counted(self):
        html = ("<html><body><p>satu dua tiga</p>"
                "<script>empat lima enam tujuh delapan sembilan</script>"
                "<style>sebelas duabelas tigabelas</style></body></html>")
        insp = PageInspector("http://x.onion/")
        insp.feed(html)
        self.assertEqual(insp.summary()["words"], 3)

    # L20: meta descriptions are kept up to 300 chars.
    def test_description_kept_to_300_chars(self):
        desc = "x" * 100
        html = ('<html><head><meta name="description" content="%s"></head>'
                "<body></body></html>") % desc
        insp = PageInspector("http://x.onion/")
        insp.feed(html)
        self.assertEqual(insp.summary()["description"], desc)
