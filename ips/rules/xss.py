# -*- coding: utf-8 -*-
"""
Luật 2: Cross-Site Scripting (XSS)
Dữ liệu chứa thẻ HTML hoặc sự kiện JavaScript, thứ người dùng thật không gõ vào ô nhập liệu.
"""

from .. import config
from . import base

MA = "xss"
TEN = "XSS"
MUC_DO = "CAO"
PHAN_HOI = 403
CHE_TAI = config.CONG_DIEM

MAU = base.bien_dich(
    r"<script",
    r"<iframe",
    r"onerror\s*=",
    r"onload\s*=",
    r"\bon(mouseover|mouseenter|focus|click)\s*=",
    r"javascript:",
    r"document\.cookie",
    r"<img[^>]+src",
)


def kiem_tra(req, lich_su):
    return base.tim(req, MAU)
