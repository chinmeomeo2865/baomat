# -*- coding: utf-8 -*-
"""
Luật 6: DDoS (phân tán)
Tổng lưu lượng tăng vọt VÀ đến từ nhiều IP khác nhau cùng lúc. Mỗi IP gửi ít nên lọt luật DoS,
vì vậy chế tài là bật chế độ khẩn cấp toàn hệ thống thay vì phạt từng IP.
"""

from .. import config

MA = "ddos"
TEN = "DDoS"
MUC_DO = "CAO"
PHAN_HOI = 429
CHE_TAI = config.KHAN_CAP


def kiem_tra(req, lich_su):
    tong = len(lich_su) + 1
    so_ip = len({r["ip"] for r in lich_su} | {req["ip"]})
    if tong > config.DDOS_TONG and so_ip > config.DDOS_SO_IP:
        return f"{tong} request từ {so_ip} IP trong {config.CUA_SO} giây"
    return None
