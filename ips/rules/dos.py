# -*- coding: utf-8 -*-
"""
Luật 5: DoS (một nguồn)
Một IP gửi quá nhiều request trong cửa sổ trượt. Từng request có thể hoàn toàn hợp lệ,
nguy hiểm nằm ở số lượng.
"""

from .. import config

MA = "dos"
TEN = "DoS"
MUC_DO = "CAO"
PHAN_HOI = 429
CHE_TAI = config.CONG_DIEM   # mỗi request vượt ngưỡng +1 điểm: cố bắn tiếp là bị khoá


def kiem_tra(req, lich_su):
    so = sum(1 for r in lich_su if r["ip"] == req["ip"]) + 1   # +1: tính cả request này
    if so > config.DOS_NGUONG:
        return f"IP gửi {so} request trong {config.CUA_SO} giây (ngưỡng {config.DOS_NGUONG})"
    return None
