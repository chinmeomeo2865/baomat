# -*- coding: utf-8 -*-
"""
storage.py
Bộ nhớ của IPS: lịch sử request (RAM), cảnh báo gần nhất, và file log trên đĩa.
Mọi thao tác đọc/ghi trạng thái phải giữ LOCK (server chạy đa luồng).
"""

import threading
import time
from collections import deque
from datetime import datetime

from . import config

LOCK = threading.RLock()

_REQUESTS = deque(maxlen=config.SO_REQUEST_LUU)
_CANH_BAO = deque(maxlen=config.SO_CANH_BAO_LUU)
_dem = {"tong": 0, "id": 0}


def bay_gio():
    """Đồng hồ duy nhất của IPS (test thay hàm này để giả lập thời gian)."""
    return time.time()


def gio_dep(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def them(ban_ghi):
    """Lưu 1 request đã xử lý, gán id, ghi ra file log. Trả về chính bản ghi."""
    _dem["tong"] += 1
    _dem["id"] += 1
    ban_ghi["id"] = _dem["id"]
    _REQUESTS.append(ban_ghi)
    _ghi_file_log(ban_ghi)
    return ban_ghi


def trong_cua_so(now):
    """Các request trong CUA_SO giây gần nhất (duyệt từ mới về cũ, dừng khi quá cửa sổ)."""
    ket_qua = []
    for r in reversed(_REQUESTS):
        if now - r["ts"] > config.CUA_SO:
            break
        ket_qua.append(r)
    return ket_qua


def tat_ca():
    return list(_REQUESTS)


def tong_request():
    return _dem["tong"]


def canh_bao(muc, noi_dung):
    """Thêm 1 cảnh báo. muc: 'nguy_hiem' | 'canh_bao' | 'thong_tin'."""
    now = bay_gio()
    _CANH_BAO.append({"ts": now, "tg": gio_dep(now), "muc": muc, "noi_dung": noi_dung})
    try:
        print(f"[IPS {gio_dep(now)}] {noi_dung}", flush=True)
    except (UnicodeEncodeError, OSError):
        pass   # terminal không in được tiếng Việt: bỏ qua, cảnh báo vẫn có trên dashboard


def ds_canh_bao():
    return list(reversed(_CANH_BAO))


def xoa_het():
    _REQUESTS.clear()
    _CANH_BAO.clear()
    _dem["tong"] = 0


def _ghi_file_log(r):
    """Ghi 1 dòng Combined Log Format (giống Nginx) ra FILE_LOG."""
    url = r["url"]
    # Mã hoá ký tự làm hỏng dòng log để mỗi request đúng 1 dòng
    for k, v in (("%", "%25"), ('"', "%22"), ("\n", "%0A"), ("\r", "%0D"), (" ", "%20")):
        url = url.replace(k, v)

    def tho(s):
        return s.replace('"', "\\x22").replace("\n", "\\x0A").replace("\r", "\\x0D")

    tg = datetime.fromtimestamp(r["ts"]).astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
    dong = (f'{r["ip"]} - - [{tg}] "{r["method"]} {url} HTTP/1.1" {r["status"]} - '
            f'"{tho(r["referer"] or "-")}" "{tho(r["agent"])}"\n')
    try:
        with open(config.FILE_LOG, "a", encoding="utf-8") as f:
            f.write(dong)
    except OSError:
        pass   # lỗi ghi file không được làm sập IPS
