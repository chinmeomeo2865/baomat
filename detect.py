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
    r"(?i)\bunion\b.+\bselect\b",
    r"(?i)\bor\b\s+\d+\s*=\s*\d+",     # or 1=1
    r"(?i)'\s*or\s*'",                  # ' or '
    r"(?i)\bselect\b.+\bfrom\b",
    r"(?i)\bsleep\s*\(",               # time-based
    r"(?i)\bbenchmark\s*\(",
    r"(?i)information_schema",
    r"(?i)('|\s)--",                    # comment sql (vd: admin'--)
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


def kiem_tra_request(e):
    """
    Nhận vào 1 dòng log (dictionary), trả về danh sách cảnh báo.
    Mỗi cảnh báo: (loại, mức_độ, chi_tiết)
    """
    canh_bao = []
    url = unquote(e.get("url", ""))     # giải mã URL (vd %27 -> ')
    agent = e.get("agent", "")

    # 1) SQL Injection
    for p in SQLI:
        if re.search(p, url):
            canh_bao.append(("SQL Injection", "CAO", url[:120]))
            break

    # 2) XSS
    for p in XSS:
        if re.search(p, url):
            canh_bao.append(("XSS", "CAO", url[:120]))
            break

    # 3) Công cụ quét lỗ hổng
    ua = agent.lower()
    for c in CONG_CU:
        if c in ua:
            canh_bao.append(("Công cụ quét: " + c, "CAO", agent[:120]))
            break

    # 4) Dò tìm đường dẫn nhạy cảm
    low = url.lower()
    for d in DUONG_DAN_NHAY_CAM:
        if d in low:
            canh_bao.append(("Dò tìm đường dẫn nhạy cảm", "TRUNG BÌNH", url[:120]))
            break

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
