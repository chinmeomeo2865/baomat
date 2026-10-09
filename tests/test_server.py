# -*- coding: utf-8 -*-
"""
Kiểm thử toàn bộ IPS qua server: chặn, chế tài theo bậc, khẩn cấp DDoS, quản trị, file log.
Dùng đồng hồ giả (thay storage.bay_gio) để kiểm tra thời gian khoá mà không phải chờ.

Cách chạy (từ thư mục gốc project):
    python -m unittest discover -s tests -t . -v
"""

import os
import tempfile
import unittest
from unittest import mock

import server
from ips import config, sanctions, storage

ADMIN = {"X-IPS-Admin": "1"}


class DongHoGia:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t

    def tien(self, giay):
        self.t += giay


class CoSo(unittest.TestCase):

    def setUp(self):
        fd, self.file_log = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        self.p_log = mock.patch.object(config, "FILE_LOG", self.file_log)
        self.p_log.start()
        self.gio = DongHoGia()
        self.p_gio = mock.patch.object(storage, "bay_gio", self.gio)
        self.p_gio.start()
        storage.xoa_het()
        sanctions.xoa_het()
        # use_cookies=False: để test client gửi nguyên header Cookie tự đặt
        self.c = server.app.test_client(use_cookies=False)

    def tearDown(self):
        self.p_gio.stop()
        self.p_log.stop()
        os.remove(self.file_log)

    def goi(self, path, ip="1.1.1.1", **headers):
        r = self.c.get(path, headers={"X-Forwarded-For": ip, **headers})
        return r.status_code, r.get_json(), r


class TestChanVaChoQua(CoSo):

    def test_sach_thi_cho_qua(self):
        code, j, _ = self.goi("/products")
        self.assertEqual(code, 200)
        self.assertEqual(j["trang_thai"], "cho_qua")

    def test_noi_dung_doc_hai_bi_403(self):
        self.assertEqual(self.goi("/p?id=1' OR '1'='1", ip="2.0.0.1")[0], 403)
        self.assertEqual(self.goi("/s?q=<script>alert(1)</script>", ip="2.0.0.2")[0], 403)
        self.assertEqual(self.goi("/.env", ip="2.0.0.3")[0], 403)
        self.assertEqual(self.goi("/", ip="2.0.0.4", **{"Cookie": "x=<script>alert(1)</script>"})[0], 403)
        r = self.c.post("/login", json={"user": "admin'--"}, headers={"X-Forwarded-For": "2.0.0.5"})
        self.assertEqual(r.status_code, 403)

    def test_body_dai_van_bi_quet_va_body_qua_lon_bi_413(self):
        r = self.c.post("/login", data="a" * 5000 + " ' OR '1'='1", headers={"X-Forwarded-For": "2.0.0.6"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.c.post("/up", data="a" * (2 * 1024 * 1024)).status_code, 413)


class TestCheTai(CoSo):

    SQLI = "/login?user=admin'--"

    def test_ba_diem_thi_khoa_ip(self):
        self.assertIn("(1/3)", self.goi(self.SQLI)[1]["che_tai"])
        self.assertIn("(2/3)", self.goi(self.SQLI)[1]["che_tai"])
        self.assertIn("Khoá IP 5 phút (lần 1)", self.goi(self.SQLI)[1]["che_tai"])
        code, j, _ = self.goi("/products")          # request sạch vẫn bị từ chối
        self.assertEqual((code, j["trang_thai"]), (403, "ip_bi_khoa"))

    def test_cong_cu_quet_bi_khoa_ngay(self):
        code, j, _ = self.goi("/", ip="3.3.3.3", **{"User-Agent": "sqlmap/1.7"})
        self.assertEqual(code, 403)
        self.assertIn("Khoá IP 5 phút", j["che_tai"])
        self.assertEqual(self.goi("/", ip="3.3.3.3")[1]["trang_thai"], "ip_bi_khoa")

    def test_khoa_theo_bac_5_15_60_phut(self):
        for lan, phut in [(1, 5), (2, 15), (3, 60), (4, 60)]:
            for _ in range(2):
                self.goi(self.SQLI)
            self.assertIn(f"Khoá IP {phut} phút (lần {lan})", self.goi(self.SQLI)[1]["che_tai"])
            self.gio.tien(phut * 60 + 1)                # hết hạn khoá
            self.assertEqual(self.goi("/products")[0], 200)

    def test_diem_vi_pham_het_han_sau_10_phut(self):
        self.goi(self.SQLI)
        self.goi(self.SQLI)
        self.gio.tien(config.THOI_HAN_DIEM + 1)
        self.assertIn("(1/3)", self.goi(self.SQLI)[1]["che_tai"])

    def test_dos_429_kem_retry_after_roi_bi_khoa(self):
        codes = [self.goi("/", ip="4.4.4.4")[0] for _ in range(config.DOS_NGUONG)]
        self.assertEqual(set(codes), {200})
        code, j, r = self.goi("/", ip="4.4.4.4")
        self.assertEqual(code, 429)
        self.assertEqual(r.headers["Retry-After"], str(config.RETRY_AFTER))
        self.goi("/", ip="4.4.4.4")
        self.assertIn("Khoá IP", self.goi("/", ip="4.4.4.4")[1]["che_tai"])
        self.assertEqual(self.goi("/", ip="4.4.4.4")[1]["trang_thai"], "ip_bi_khoa")

    def test_khong_tin_xff_tu_may_ngoai(self):
        ngoai = {"REMOTE_ADDR": "10.9.9.9"}
        for i in range(config.DOS_NGUONG + 1):
            r = self.c.get("/", headers={"X-Forwarded-For": f"7.7.7.{i}"}, environ_base=ngoai)
        self.assertEqual(r.status_code, 429)          # đổi XFF liên tục vẫn bị tính là 1 IP
        self.assertEqual(storage.tat_ca()[-1]["ip"], "10.9.9.9")


class TestKhanCapDDoS(CoSo):

    def test_ip_quen_van_vao_ip_la_bi_429(self):
        for ip in ("10.0.0.1", "10.0.0.2"):
            self.assertEqual(self.goi("/products", ip=ip)[0], 200)
        self.gio.tien(30)

        codes = [self.goi("/", ip=f"66.0.0.{i}")[0] for i in range(config.DDOS_TONG + 5)]
        self.assertIn(200, codes[:config.DDOS_TONG])      # đầu đợt flood còn lọt
        self.assertEqual(codes[-1], 429)                  # vượt ngưỡng thì khẩn cấp
        self.assertTrue(sanctions.khan_cap_dang_bat())

        code, j, _ = self.goi("/products", ip="10.0.0.1")
        self.assertEqual(code, 200)                        # người dùng thật vẫn vào được
        self.assertEqual(self.goi("/products", ip="66.0.0.0")[0], 429)   # bot lọt đầu đợt KHÔNG được coi là quen
        self.assertEqual(self.goi("/products", ip="99.9.9.9")[0], 429)   # IP lạ
        self.assertEqual(sanctions.diem_hien_tai("99.9.9.9", self.gio()), 0)   # DDoS không tính điểm

        self.gio.tien(config.KHAN_CAP_TAT_SAU + config.CUA_SO + 1)
        self.assertFalse(self.c.get("/__data").get_json()["khan_cap"]["bat"])
        self.assertEqual(self.goi("/products", ip="99.9.9.9")[0], 200)


class TestQuanTriVaGiaoDien(CoSo):

    def test_mo_khoa_can_quyen_quan_tri(self):
        self.goi("/", ip="3.3.3.3", **{"User-Agent": "sqlmap/1.7"})
        ngoai = {"REMOTE_ADDR": "10.9.9.9"}
        self.assertEqual(self.c.post("/__unban", json={"ip": "3.3.3.3"}).status_code, 403)
        self.assertEqual(self.c.post("/__unban", json={"ip": "3.3.3.3"}, headers=ADMIN, environ_base=ngoai).status_code, 403)
        r = self.c.post("/__unban", json={"ip": "3.3.3.3"}, headers=ADMIN)
        self.assertTrue(r.get_json()["ok"])
        self.assertEqual(self.goi("/products", ip="3.3.3.3")[0], 200)

    def test_reset_xoa_ca_danh_sach_khoa(self):
        self.goi("/", ip="3.3.3.3", **{"User-Agent": "sqlmap/1.7"})
        self.assertEqual(self.c.post("/__reset").status_code, 403)
        self.assertEqual(self.c.post("/__reset", headers=ADMIN).status_code, 200)
        self.assertEqual(self.goi("/", ip="3.3.3.3")[0], 200)
        self.assertEqual(self.c.get("/__data").get_json()["tong"], 1)

    def test_api_du_lieu(self):
        self.goi("/products")
        self.goi("/p?id=1' OR '1'='1", ip="2.2.2.2")
        d = self.c.get("/__data").get_json()
        for k in ("tong", "cho_qua", "bi_chan", "luat", "theo_loai", "bieu_do", "ds_khoa", "canh_bao", "khan_cap", "rows"):
            self.assertIn(k, d)
        self.assertEqual((d["tong"], d["cho_qua"], d["bi_chan"]), (2, 1, 1))
        self.assertEqual(d["theo_loai"]["sqli"], 1)
        self.assertEqual(len(d["bieu_do"]["cho_qua"]), 30)

    def test_trang_giam_sat(self):
        r = self.c.get("/__monitor")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Hệ thống ngăn chặn tấn công web", r.get_data(as_text=True))

    def test_file_log(self):
        self.goi("/products")
        self.goi("/p?id=1' OR '1'='1", ip="2.2.2.2")
        self.goi("/a%0Ab%22c", ip="2.2.2.3", **{"User-Agent": 'Evil "quoted" agent'})
        with open(self.file_log, encoding="utf-8") as f:
            dong = f.read().splitlines()
        self.assertEqual(len(dong), 3)                    # mỗi request đúng 1 dòng
        self.assertIn('" 403 -', dong[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
