# -*- coding: utf-8 -*-
"""
base.py
Phần dùng chung cho các luật nội dung: chuẩn hoá request và tìm mẫu trong từng trường.
"""

import re
from urllib.parse import unquote_plus


def giai_ma(s, so_lan=3):
    """Giải mã %xx lặp lại tới khi ổn định (chống mã hoá nhiều lớp như %2527 -> %27 -> ')."""
    for _ in range(so_lan):
        moi = unquote_plus(s)
        if moi == s:
            break
        s = moi
    return s


def chuan_hoa(req):
    """Trả về bản sao request với các trường do kẻ tấn công điều khiển đã được giải mã."""
    ban = dict(req)
    for k in ("url", "body", "referer", "cookie"):
        ban[k] = giai_ma(ban.get(k) or "")
    ban["agent"] = ban.get("agent") or ""
    return ban


def bien_dich(*mau, co=re.IGNORECASE):
    """Biên dịch sẵn các biểu thức chính quy của một luật."""
    return [re.compile(m, co) for m in mau]


def cac_truong(req):
    """5 trường kẻ tấn công kiểm soát được, theo thứ tự quét."""
    return [
        ("URL", req.get("url", "")),
        ("Body", req.get("body", "")),
        ("Referer", req.get("referer", "")),
        ("Cookie", req.get("cookie", "")),
        ("User-Agent", req.get("agent", "")),
    ]


def tim(req, mau, bien_doi=None):
    """
    Quét riêng từng trường, trả về chi tiết của trường đầu tiên khớp một mẫu, hoặc None.
    bien_doi: hàm tạo thêm một phiên bản đã chuẩn hoá của trường để so cùng (vd bỏ comment SQL).
    """
    for ten, gia_tri in cac_truong(req):
        if not gia_tri:
            continue
        cac_ban = [gia_tri] if bien_doi is None else [gia_tri, bien_doi(gia_tri)]
        if any(m.search(b) for b in cac_ban for m in mau):
            return gia_tri[:120] if ten == "URL" else f"[{ten}] {gia_tri[:110]}"
    return None
