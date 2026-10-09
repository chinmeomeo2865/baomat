# -*- coding: utf-8 -*-
"""
Luật 4: Dò tìm đường dẫn nhạy cảm (Forced Browsing)
Đoán tên file cấu hình, mã nguồn, trang quản trị không được liên kết công khai.
"""

import re

from .. import config

MA = "sensitive_path"
TEN = "Dò đường dẫn nhạy cảm"
MUC_DO = "TB"
PHAN_HOI = 403
CHE_TAI = config.CONG_DIEM

DUONG_DAN = [
    "/wp-admin", "/wp-login", "/phpmyadmin", "/.env", "/.git",
    "/admin", "/config", "/shell", "/cmd", "/.aws", "/backup",
]

# So khớp TÊN ĐẦY ĐỦ của một đoạn đường dẫn, không so chuỗi con:
#   /admin, /admin/users, /backup.zip, /.env.bak  -> khớp
#   /administrator-guide, /configure-help          -> KHÔNG khớp (tránh chặn nhầm)
MAU = re.compile(
    r"(?i)/(?:" + "|".join(re.escape(d.lstrip("/")) for d in DUONG_DAN) + r")"
    r"(?=[/?.#\s]|$)"
)


def kiem_tra(req, lich_su):
    # Chỉ xét URL: quản trị viên đi từ trang /admin sang trang khác (Referer) là bình thường
    url = req.get("url", "")
    return url[:120] if MAU.search(url) else None
