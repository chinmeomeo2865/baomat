# -*- coding: utf-8 -*-
"""
Gom 6 luật về một chỗ. Mỗi file luật khai báo cùng một bộ:

    MA        khoá dùng trong code/JSON
    TEN       tên hiển thị
    MUC_DO    "CAO" | "TB"
    PHAN_HOI  mã HTTP khi luật quyết định chặn (403 nội dung, 429 tần suất)
    CHE_TAI   config.CONG_DIEM | config.KHOA_NGAY | config.KHAN_CAP
    kiem_tra(req, lich_su) -> chuỗi chi tiết nếu vi phạm, None nếu sạch
"""

from . import sqli, xss, scanner, sensitive_path, dos, ddos

# 4 luật nội dung (xét từng request) + 2 luật tần suất (xét lịch sử trong cửa sổ trượt)
CAC_LUAT = [sqli, xss, scanner, sensitive_path, dos, ddos]
