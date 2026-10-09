# -*- coding: utf-8 -*-
"""
Kiểm thử từng file luật trong ips/rules/.

Cách chạy (từ thư mục gốc project):
    python -m unittest discover -s tests -t . -v
"""

import unittest

from ips import config
from ips.rules import CAC_LUAT, base, ddos, dos, scanner, sensitive_path, sqli, xss


def req(url="/", **kw):
    return base.chuan_hoa({"ip": kw.pop("ip", "1.1.1.1"), "url": url, **kw})


class TestCauTrucLuat(unittest.TestCase):

    def test_moi_luat_khai_bao_du_thanh_phan(self):
        self.assertEqual(len(CAC_LUAT), 6)
        for luat in CAC_LUAT:
            for ten in ("MA", "TEN", "MUC_DO", "PHAN_HOI", "CHE_TAI", "kiem_tra"):
                self.assertTrue(hasattr(luat, ten), f"{luat.__name__} thiếu {ten}")
            self.assertIn(luat.PHAN_HOI, (403, 429))
            self.assertIn(luat.CHE_TAI, (config.CONG_DIEM, config.KHOA_NGAY, config.KHAN_CAP))


class TestSQLi(unittest.TestCase):

    TAN_CONG = [
        "admin'--", "admin'#", "admin' -- ", "' OR '1'='1", "' OR 'a'='a", "1 OR 1=1",
        "1' OR 1=1--", "' OR 2>1--", "1 or true", "' || '1'='1",
        "1 UNION SELECT user,pass FROM users", "1/**/UNION/**/SELECT/**/1",
        "1 UN/**/ION SE/**/LECT 1", "1%0aUNION%0aSELECT%0a1", "1+UNION+SELECT+1",
        "1 AND SLEEP(5)", "1' AND '1'='1", "1 AND 1=1", "1' AND 1=2--",
        "1; DROP TABLE users--", "1; DROP TABLE users", "%2527%20OR%201=1",
        "1 AND extractvalue(1,concat(0x7e,@@version))", "1 UNION SELECT table_name FROM information_schema.tables",
    ]
    BINH_THUONG = [
        "/products", "/search?q=rock 'n' roll", "/blog/a -- b", "/search?q=select a gift from our shop",
        "/search?q=cats or dogs", "/products?sort=select_from_list", "/?q=1+1=2",
        "/books?q=O'Reilly or Packt", "/search?q=fish and chips", "/search?q=C%2B%2B tutorial",
        "/login?user=alice&pass=123", "/?q=it's great",
    ]

    def test_bat_payload(self):
        for p in self.TAN_CONG:
            self.assertIsNotNone(sqli.kiem_tra(req("/?q=" + p), []), p)

    def test_khong_chan_nham(self):
        for u in self.BINH_THUONG:
            self.assertIsNone(sqli.kiem_tra(req(u), []), u)

    def test_quet_ca_body_cookie_referer_useragent(self):
        self.assertIn("[Body]", sqli.kiem_tra(req("/login", body='{"user": "admin\'--"}'), []))
        self.assertIn("[Cookie]", sqli.kiem_tra(req("/", cookie="sid=1' OR '1'='1"), []))
        self.assertIn("[Referer]", sqli.kiem_tra(req("/", referer="http://x/?id=1 union select 1"), []))
        self.assertIn("[User-Agent]", sqli.kiem_tra(req("/", agent="' or 1=1--"), []))


class TestXSS(unittest.TestCase):

    def test_bat_payload(self):
        for p in ["<script>alert(1)</script>", "<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>",
                  "javascript:alert(1)", "<iframe src=//evil>", "<a onmouseover=alert(1)>",
                  "%3Cscript%3Ealert(1)%3C%2Fscript%3E"]:
            self.assertIsNotNone(xss.kiem_tra(req("/?q=" + p), []), p)
        self.assertIn("[Cookie]", xss.kiem_tra(req("/", cookie="x=<script>alert(1)</script>"), []))

    def test_khong_chan_nham(self):
        for u in ["/products", "/?online=1", "/search?q=script writing tips", "/?q=a < b"]:
            self.assertIsNone(xss.kiem_tra(req(u), []), u)


class TestCongCuQuet(unittest.TestCase):

    def test_bat_theo_user_agent(self):
        for ua in ["sqlmap/1.7", "Nikto/2.5", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "gobuster/3.6"]:
            self.assertIsNotNone(scanner.kiem_tra(req("/", agent=ua), []), ua)
        self.assertIsNone(scanner.kiem_tra(req("/", agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"), []))

    def test_khoa_ngay(self):
        self.assertEqual(scanner.CHE_TAI, config.KHOA_NGAY)


class TestDuongDanNhayCam(unittest.TestCase):

    def test_bat(self):
        for u in ["/admin", "/admin/users", "/.env", "/.env.bak", "/.git/config", "/wp-admin/", "/backup.zip"]:
            self.assertIsNotNone(sensitive_path.kiem_tra(req(u), []), u)

    def test_khong_chan_nham(self):
        for u in ["/products", "/administrator-guide", "/configure-help"]:
            self.assertIsNone(sensitive_path.kiem_tra(req(u), []), u)
        # /admin nằm trong Referer thì không tính là dò đường dẫn
        self.assertIsNone(sensitive_path.kiem_tra(req("/products", referer="http://site/admin"), []))


class TestTanSuat(unittest.TestCase):

    def test_dos_vuot_nguong(self):
        lich_su = [{"ip": "9.9.9.9"}] * config.DOS_NGUONG
        self.assertIsNotNone(dos.kiem_tra(req(ip="9.9.9.9"), lich_su))
        self.assertIsNone(dos.kiem_tra(req(ip="9.9.9.9"), lich_su[:-1]))
        self.assertIsNone(dos.kiem_tra(req(ip="8.8.8.8"), lich_su))   # IP khác không bị tính

    def test_ddos_can_ca_tong_va_so_ip(self):
        nhieu_ip = [{"ip": f"5.5.5.{i % 20}"} for i in range(config.DDOS_TONG)]
        it_ip = [{"ip": f"5.5.5.{i % 3}"} for i in range(config.DDOS_TONG)]
        self.assertIsNotNone(ddos.kiem_tra(req(ip="6.6.6.6"), nhieu_ip))
        self.assertIsNone(ddos.kiem_tra(req(ip="6.6.6.6"), it_ip))           # ít IP: là DoS, không phải DDoS
        self.assertIsNone(ddos.kiem_tra(req(ip="6.6.6.6"), nhieu_ip[:10]))   # nhiều IP nhưng tổng thấp


if __name__ == "__main__":
    unittest.main(verbosity=2)
