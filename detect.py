# -*- coding: utf-8 -*-
"""
detect.py
Chứa toàn bộ "luật" (rule) để phát hiện tấn công từ log web.

Có 2 nhóm luật:
  A. Kiểm tra TỪNG request (SQLi, XSS, công cụ quét, đường dẫn nhạy cảm)
  B. Kiểm tra THEO NHÓM request trong 1 phút (DoS, DDoS)
"""

import re
from urllib.parse import unquote
from collections import defaultdict

# =========================================================
# NGƯỠNG CẢNH BÁO - bạn có thể chỉnh để demo cho dễ thấy
# =========================================================
DOS_NGUONG = 100     # 1 IP gửi > 100 request / phút  => nghi DoS
DDOS_TONG = 300      # tổng > 300 request / phút       => nghi DDoS
DDOS_SO_IP = 50      # và có > 50 IP khác nhau          => nghi DDoS


# =========================================================
# NHÓM A: LUẬT KIỂM TRA TỪNG REQUEST
# =========================================================

# Dấu hiệu SQL Injection
SQLI = [
    r"(?is)\bunion\b.+\bselect\b",     # (?s): "." khớp cả xuống dòng (chống lách bằng %0a)
    r"(?i)\bor\b\s+\d+\s*=\s*\d+",     # or 1=1
    r"(?i)'\s*or\s*'",                  # ' or '
    r"(?is)\bselect\b.+\bfrom\b",
    r"(?i)\bsleep\s*\(",               # time-based
    r"(?i)\bbenchmark\s*\(",
    r"(?i)information_schema",
    r"'\s*(--|#)",                      # đóng chuỗi rồi comment sql (vd: admin'--, admin'#)
    r";\s*--",                          # kết thúc câu lệnh rồi comment (vd: 1;--)
    r"(?i)@@version",
]

# Dấu hiệu XSS
XSS = [
    r"(?i)<script",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)javascript:",
    r"(?i)document\.cookie",
    r"(?i)<img[^>]+src",
]

# Công cụ tấn công / quét lỗ hổng (nhận qua User-Agent)
CONG_CU = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
    "gobuster", "hydra", "wpscan", "acunetix", "nessus", "fuzz",
]

# Đường dẫn nhạy cảm - hacker hay dò tìm
DUONG_DAN_NHAY_CAM = [
    "/wp-admin", "/wp-login", "/phpmyadmin", "/.env", "/.git",
    "/admin", "/config", "/shell", "/cmd", "/.aws", "/backup",
]

# So khớp theo TÊN ĐẦY ĐỦ của 1 đoạn đường dẫn, không so chuỗi con:
#   /admin, /admin/users, /backup.zip, /.env.bak  -> khớp
#   /administrator-guide, /configure-help          -> KHÔNG khớp (tránh chặn nhầm)
DUONG_DAN_RE = re.compile(
    r"(?i)/(?:" + "|".join(re.escape(d.lstrip("/")) for d in DUONG_DAN_NHAY_CAM) + r")"
    r"(?=[/?.#\s]|$)"
)


def kiem_tra_request(e):
    """
    Nhận vào 1 dòng log (dictionary), trả về danh sách cảnh báo.
    Mỗi cảnh báo: (loại, mức_độ, chi_tiết)

    SQLi/XSS được quét trên MỌI chỗ kẻ tấn công kiểm soát được: URL, body,
    Referer, Cookie, User-Agent. Còn luật đường dẫn nhạy cảm chỉ xét URL.
    """
    canh_bao = []
    url = unquote(e.get("url", ""))     # giải mã URL (vd %27 -> ')
    agent = e.get("agent", "")
    referer = e.get("referer", "")
    if referer == "-":                  # "-" trong log nghĩa là không có Referer
        referer = ""
    # Quét riêng từng trường (không nối chuỗi) để chi tiết cảnh báo chỉ rõ
    # payload nằm ở đâu, và tránh khớp nhầm giữa 2 trường khác nhau
    cac_truong = [
        ("URL", url), ("Body", e.get("body", "")), ("Referer", unquote(referer)),
        ("Cookie", unquote(e.get("cookie", ""))), ("User-Agent", agent),
    ]

    def tim(mau):
        """Trả về chi tiết của trường đầu tiên khớp 1 trong các mẫu, hoặc None."""
        for ten, gia_tri in cac_truong:
            if gia_tri and any(re.search(p, gia_tri) for p in mau):
                return gia_tri[:120] if ten == "URL" else f"[{ten}] {gia_tri[:110]}"
        return None

    # 1) SQL Injection
    ct = tim(SQLI)
    if ct:
        canh_bao.append(("SQL Injection", "CAO", ct))

    # 2) XSS
    ct = tim(XSS)
    if ct:
        canh_bao.append(("XSS", "CAO", ct))

    # 3) Công cụ quét lỗ hổng
    ua = agent.lower()
    for c in CONG_CU:
        if c in ua:
            canh_bao.append(("Công cụ quét: " + c, "CAO", agent[:120]))
            break

    # 4) Dò tìm đường dẫn nhạy cảm
    if DUONG_DAN_RE.search(url):
        canh_bao.append(("Dò tìm đường dẫn nhạy cảm", "TRUNG BÌNH", url[:120]))

    return canh_bao


# =========================================================
# NHÓM B: LUẬT KIỂM TRA THEO NHÓM (DoS / DDoS)
# =========================================================

def kiem_tra_theo_phut(entries):
    """
    Gom các request theo từng PHÚT, rồi kiểm tra DoS và DDoS.
    Trả về danh sách cảnh báo: (loại, mức_độ, chi_tiết)
    """
    canh_bao = []

    # Gom log theo phút: { "2025-10-10 13:55": [entry, entry, ...] }
    theo_phut = defaultdict(list)
    for e in entries:
        if e["dt"]:
            khoa = e["dt"].strftime("%Y-%m-%d %H:%M")
            theo_phut[khoa].append(e)

    for phut, ds in theo_phut.items():
        tong = len(ds)

        # Đếm số request của từng IP trong phút này
        dem_ip = defaultdict(int)
        for e in ds:
            dem_ip[e["ip"]] += 1

        # ---- DoS: 1 IP gửi quá nhiều ----
        for ip, so in dem_ip.items():
            if so > DOS_NGUONG:
                canh_bao.append((
                    "DoS",
                    "CAO",
                    f"IP {ip} gửi {so} request trong phút {phut}",
                ))

        # ---- DDoS: tổng cao + nhiều IP khác nhau ----
        so_ip = len(dem_ip)
        if tong > DDOS_TONG and so_ip > DDOS_SO_IP:
            canh_bao.append((
                "DDoS",
                "CAO",
                f"Phút {phut}: {tong} request từ {so_ip} IP khác nhau",
            ))

    return canh_bao


# =========================================================
# HÀM PHỤ: lấy tập IP bị DoS và tập phút bị DDoS
# (dùng để đánh dấu TỪNG request trên dashboard)
# =========================================================

def ip_bi_dos(entries):
    """Trả về tập các IP gây DoS (gửi quá nhiều request trong 1 phút)."""
    dem = defaultdict(lambda: defaultdict(int))   # {phut: {ip: so}}
    for e in entries:
        if e["dt"]:
            phut = e["dt"].strftime("%Y-%m-%d %H:%M")
            dem[phut][e["ip"]] += 1

    ket_qua = set()
    for phut, theo_ip in dem.items():
        for ip, so in theo_ip.items():
            if so > DOS_NGUONG:
                ket_qua.add(ip)
    return ket_qua


def phut_bi_ddos(entries):
    """Trả về tập các phút (chuỗi 'Y-m-d H:M') bị DDoS."""
    theo_phut = defaultdict(list)
    for e in entries:
        if e["dt"]:
            theo_phut[e["dt"].strftime("%Y-%m-%d %H:%M")].append(e)

    ket_qua = set()
    for phut, ds in theo_phut.items():
        so_ip = len(set(e["ip"] for e in ds))
        if len(ds) > DDOS_TONG and so_ip > DDOS_SO_IP:
            ket_qua.add(phut)
    return ket_qua


# =========================================================
# HÀM TỔNG HỢP: chạy hết tất cả luật trên toàn bộ log
# =========================================================

def phan_tich(entries):
    """Chạy tất cả luật, trả về danh sách cảnh báo đầy đủ."""
    ket_qua = []

    # Nhóm A - từng request
    for e in entries:
        for (loai, muc, ct) in kiem_tra_request(e):
            ket_qua.append({
                "thoi_gian": e["dt"].strftime("%H:%M:%S") if e["dt"] else "?",
                "ip": e["ip"],
                "loai": loai,
                "muc_do": muc,
                "chi_tiet": ct,
            })

    # Nhóm B - theo phút
    for (loai, muc, ct) in kiem_tra_theo_phut(entries):
        ket_qua.append({
            "thoi_gian": "-",
            "ip": "-",
            "loai": loai,
            "muc_do": muc,
            "chi_tiet": ct,
        })

    return ket_qua
