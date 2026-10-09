# -*- coding: utf-8 -*-
"""
Luật 3: Công cụ quét lỗ hổng
Công cụ trinh sát tự động thường tự khai tên trong User-Agent. Ý đồ rõ ràng nên khoá IP ngay.
"""

from .. import config

MA = "scanner"
TEN = "Công cụ quét"
MUC_DO = "CAO"
PHAN_HOI = 403
CHE_TAI = config.KHOA_NGAY

CONG_CU = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
    "gobuster", "hydra", "wpscan", "acunetix", "nessus", "fuzz",
]


def kiem_tra(req, lich_su):
    ua = req.get("agent", "").lower()
    for c in CONG_CU:
        if c in ua:
            return f"Công cụ: {c} · User-Agent: {req['agent'][:100]}"
    return None
