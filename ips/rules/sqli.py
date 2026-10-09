# -*- coding: utf-8 -*-
"""
Luật 1: SQL Injection
Dữ liệu người dùng bị nối thẳng vào câu SQL. Bắt các dạng: bypass bằng điều kiện
luôn đúng, union-based, boolean/time-based blind, error-based, stacked query.
"""

import re

from .. import config
from . import base

MA = "sqli"
TEN = "SQL Injection"
MUC_DO = "CAO"
PHAN_HOI = 403
CHE_TAI = config.CONG_DIEM

MAU = base.bien_dich(
    r"\bunion\b.+\bselect\b",                        # union-based
    r"\b(or|and)\b\s+[\w'\"]+\s*(=|<|>|\blike\b)",  # or 1=1, and 1=2, or 2>1, and 'a'='a
    r"'\s*(or|and)\b",                               # 1' OR ..., 1' AND ...
    r"\bor\s+true\b",                                # or true
    r"'\s*\|\|",                                     # ' || '1'='1
    r"'\s*(--|#)",                                   # admin'--, admin'#
    r"'[^&]*(--|#)\s*(&|$)",                         # 1' AND 1=2--  (comment cuối tham số)
    r";\s*--",                                       # 1;--
    r";\s*(drop|delete|update|insert|select|shutdown|exec|truncate)\b",  # stacked query
    r"\b(sleep|benchmark)\s*\(",                     # time-based blind
    r"\bwaitfor\s+delay\b",
    r"information_schema",                           # trinh sát CSDL, error-based
    r"@@version",
    co=re.IGNORECASE | re.DOTALL,                    # DOTALL: "." khớp cả xuống dòng (chống %0a)
)


def bo_comment(s):
    """Bỏ comment kiểu /**/ để UN/**/ION thành UNION trước khi so khớp."""
    return re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)


def kiem_tra(req, lich_su):
    return base.tim(req, MAU, bien_doi=bo_comment)
