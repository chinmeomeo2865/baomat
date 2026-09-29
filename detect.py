# -*- coding: utf-8 -*-
"""
detect.py
Chua toan bo "luat" (rule) de phat hien tan cong tu log web.

Co 2 nhom luat:
  A. Kiem tra TUNG request (SQLi, XSS, cong cu quet, duong dan nhay cam)
  B. Kiem tra THEO NHOM request trong 1 phut (DoS, DDoS)
"""

import re
from urllib.parse import unquote
from collections import defaultdict

# =========================================================
# NGUONG CANH BAO - ban co the chinh de demo cho de thay
# =========================================================
DOS_NGUONG = 100     # 1 IP gui > 100 request / phut  => nghi DoS
DDOS_TONG = 300      # tong > 300 request / phut       => nghi DDoS
DDOS_SO_IP = 50      # va co > 50 IP khac nhau         => nghi DDoS


# =========================================================
# NHOM A: LUAT KIEM TRA TUNG REQUEST
# =========================================================

# Dau hieu SQL Injection
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

# Dau hieu XSS
XSS = [
    r"(?i)<script",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)javascript:",
    r"(?i)document\.cookie",
    r"(?i)<img[^>]+src",
]

# Cong cu tan cong / quet lo hong (nhan qua User-Agent)
CONG_CU = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
    "gobuster", "hydra", "wpscan", "acunetix", "nessus", "fuzz",
]

# Duong dan nhay cam - hacker hay do tim
DUONG_DAN_NHAY_CAM = [
    "/wp-admin", "/wp-login", "/phpmyadmin", "/.env", "/.git",
    "/admin", "/config", "/shell", "/cmd", "/.aws", "/backup",
]


def kiem_tra_request(e):
    """
    Nhan vao 1 dong log (dictionary), tra ve danh sach canh bao.
    Moi canh bao: (loai, muc_do, chi_tiet)
    """
    canh_bao = []
    url = unquote(e.get("url", ""))     # giai ma URL (vd %27 -> ')
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

    # 3) Cong cu quet lo hong
    ua = agent.lower()
    for c in CONG_CU:
        if c in ua:
            canh_bao.append(("Cong cu quet: " + c, "CAO", agent[:120]))
            break

    # 4) Do tim duong dan nhay cam
    low = url.lower()
    for d in DUONG_DAN_NHAY_CAM:
        if d in low:
            canh_bao.append(("Do tim duong dan nhay cam", "TRUNG BINH", url[:120]))
            break

    return canh_bao


# =========================================================
# NHOM B: LUAT KIEM TRA THEO NHOM (DoS / DDoS)
# =========================================================

def kiem_tra_theo_phut(entries):
    """
    Gom cac request theo tung PHUT, roi kiem tra DoS va DDoS.
    Tra ve danh sach canh bao: (loai, muc_do, chi_tiet)
    """
    canh_bao = []

    # Gom log theo phut: { "2025-10-10 13:55": [entry, entry, ...] }
    theo_phut = defaultdict(list)
    for e in entries:
        if e["dt"]:
            khoa = e["dt"].strftime("%Y-%m-%d %H:%M")
            theo_phut[khoa].append(e)

    for phut, ds in theo_phut.items():
        tong = len(ds)

        # Dem so request cua tung IP trong phut nay
        dem_ip = defaultdict(int)
        for e in ds:
            dem_ip[e["ip"]] += 1

        # ---- DoS: 1 IP gui qua nhieu ----
        for ip, so in dem_ip.items():
            if so > DOS_NGUONG:
                canh_bao.append((
                    "DoS",
                    "CAO",
                    f"IP {ip} gui {so} request trong phut {phut}",
                ))

        # ---- DDoS: tong cao + nhieu IP khac nhau ----
        so_ip = len(dem_ip)
        if tong > DDOS_TONG and so_ip > DDOS_SO_IP:
            canh_bao.append((
                "DDoS",
                "CAO",
                f"Phut {phut}: {tong} request tu {so_ip} IP khac nhau",
            ))

    return canh_bao


# =========================================================
# HAM TONG HOP: chay het tat ca luat tren toan bo log
# =========================================================

def phan_tich(entries):
    """Chay tat ca luat, tra ve danh sach canh bao day du."""
    ket_qua = []

    # Nhom A - tung request
    for e in entries:
        for (loai, muc, ct) in kiem_tra_request(e):
            ket_qua.append({
                "thoi_gian": e["dt"].strftime("%H:%M:%S") if e["dt"] else "?",
                "ip": e["ip"],
                "loai": loai,
                "muc_do": muc,
                "chi_tiet": ct,
            })

    # Nhom B - theo phut
    for (loai, muc, ct) in kiem_tra_theo_phut(entries):
        ket_qua.append({
            "thoi_gian": "-",
            "ip": "-",
            "loai": loai,
            "muc_do": muc,
            "chi_tiet": ct,
        })

    return ket_qua
