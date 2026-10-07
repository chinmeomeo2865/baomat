# -*- coding: utf-8 -*-
"""
test_ips.py
Kiểm thử tự động cho luật phát hiện (detect.py) và server IPS (server.py).

Cách chạy:
    python -m unittest -v test_ips
"""

import os
import tempfile
import unittest

import detect
import parser
import server

ADMIN = {"X-IPS-Admin": "1"}


def loai_tan_cong(**e):
    """Chạy luật trên 1 request, trả về tập tên loại tấn công."""
    return {c[0] for c in detect.kiem_tra_request(e)}


class TestLuatPhatHien(unittest.TestCase):

    def test_sqli_co_ban(self):
        for url in ["/product?id=1' OR '1'='1",
                    "/search?q=1 UNION SELECT user,pass FROM users",
                    "/login?user=admin'--",
                    "/login?user=admin'#",
                    "/?id=1;--"]:
            self.assertIn("SQL Injection", loai_tan_cong(url=url), url)

    def test_sqli_lach_bang_xuong_dong(self):
        self.assertIn("SQL Injection", loai_tan_cong(url="/?q=SeLeCt%0a*%0afrom%0ausers"))
        self.assertIn("SQL Injection", loai_tan_cong(url="/?q=1%0aUNION%0aSELECT%0a1"))

    def test_sqli_trong_header(self):
        self.assertIn("SQL Injection", loai_tan_cong(url="/", cookie="id=1' OR '1'='1"))
        self.assertIn("SQL Injection", loai_tan_cong(url="/", referer="http://x/?q=1 union select 1"))
        self.assertIn("SQL Injection", loai_tan_cong(url="/", agent="' or 1=1--"))

    def test_xss(self):
        self.assertIn("XSS", loai_tan_cong(url="/search?q=<script>alert(1)</script>"))
        self.assertIn("XSS", loai_tan_cong(url="/", cookie="x=<svg/onload=alert(1)>"))

    def test_duong_dan_nhay_cam(self):
        for url in ["/admin", "/admin/users", "/.env", "/.env.bak",
                    "/.git/config", "/backup.zip", "/wp-admin/"]:
            self.assertIn("Dò tìm đường dẫn nhạy cảm", loai_tan_cong(url=url), url)

    def test_khong_chan_nham(self):
        for url in ["/products", "/administrator-guide", "/configure-help",
                    "/blog/a -- b", "/products?sort=select_from_list",
                    "/search?q=rock 'n' roll"]:
            self.assertEqual(loai_tan_cong(url=url, agent="Mozilla/5.0", referer="-"), set(), url)
        # /admin nằm ở Referer thì không tính là dò đường dẫn
        self.assertEqual(loai_tan_cong(url="/products", referer="http://site/admin"), set())


class TestServerIPS(unittest.TestCase):

    def setUp(self):
        fd, self.file_log = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        server.FILE_LOG = self.file_log
        server.CHE_DO_IPS = True
        server.REQUESTS.clear()
        # use_cookies=False: để test client gửi nguyên header Cookie tự đặt
        self.c = server.app.test_client(use_cookies=False)

    def tearDown(self):
        os.remove(self.file_log)

    def test_chan_va_cho_qua(self):
        self.assertEqual(self.c.get("/products").status_code, 200)
        self.assertEqual(self.c.get("/product?id=1' OR '1'='1").status_code, 403)
        self.assertEqual(self.c.get("/", headers={"User-Agent": "sqlmap/1.7"}).status_code, 403)
        self.assertEqual(self.c.post("/login", json={"user": "admin'--"}).status_code, 403)

    def test_body_dai_van_bi_quet(self):
        body = "a" * 5000 + " ' OR '1'='1"
        self.assertEqual(self.c.post("/login", data=body).status_code, 403)

    def test_body_qua_lon_bi_tu_choi(self):
        self.assertEqual(self.c.post("/up", data="a" * (2 * 1024 * 1024)).status_code, 413)

    def test_cookie_doc_bi_chan(self):
        r = self.c.get("/", headers={"Cookie": "session=<script>alert(1)</script>"})
        self.assertEqual(r.status_code, 403)

    def test_dos_bi_chan_429(self):
        codes = [self.c.get("/", headers={"X-Forwarded-For": "45.77.10.99"}).status_code
                 for _ in range(server.DOS_RT + 3)]
        self.assertEqual(codes[0], 200)
        self.assertEqual(codes[-1], 429)

    def test_khong_tin_xff_tu_may_ngoai(self):
        ngoai = {"REMOTE_ADDR": "10.0.0.5"}
        for i in range(server.DOS_RT + 3):
            r = self.c.get("/", headers={"X-Forwarded-For": f"1.1.1.{i}"}, environ_base=ngoai)
        # Đổi XFF liên tục nhưng vẫn bị tính là 1 IP thật -> dính DoS
        self.assertEqual(r.status_code, 429)
        self.assertEqual(server.REQUESTS[-1]["ip"], "10.0.0.5")

    def test_che_do_ids_cho_qua(self):
        self.c.post("/__toggle_mode", headers=ADMIN)
        self.assertFalse(server.CHE_DO_IPS)
        self.assertEqual(self.c.get("/product?id=1' OR '1'='1").status_code, 200)
        self.assertEqual(server.REQUESTS[-1]["nguy"], "CAO")   # vẫn ghi nhận cảnh báo

    def test_bao_ve_endpoint_quan_tri(self):
        ngoai = {"REMOTE_ADDR": "10.0.0.5"}
        self.c.get("/__toggle_mode")
        self.assertEqual(self.c.post("/__toggle_mode").status_code, 403)
        self.assertEqual(self.c.post("/__toggle_mode", headers=ADMIN, environ_base=ngoai).status_code, 403)
        self.assertEqual(self.c.post("/__reset", headers=ADMIN, environ_base=ngoai).status_code, 403)
        self.assertTrue(server.CHE_DO_IPS)
        self.assertEqual(self.c.post("/__toggle_mode", headers=ADMIN).status_code, 200)
        self.assertFalse(server.CHE_DO_IPS)

    def test_file_log_phan_tich_lai_duoc(self):
        self.c.get("/products")
        self.c.get("/product?id=1' OR '1'='1")
        self.c.get("/?q=SeLeCt%0a*%0afrom%0ausers")
        self.c.get("/", headers={"User-Agent": 'Evil "quoted" agent'})
        entries = parser.parse_file(self.file_log)
        self.assertEqual(len(entries), 4)
        self.assertEqual([e["status"] for e in entries], [200, 403, 403, 200])
        canh_bao = [c["loai"] for c in detect.phan_tich(entries)]
        self.assertEqual(canh_bao.count("SQL Injection"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
