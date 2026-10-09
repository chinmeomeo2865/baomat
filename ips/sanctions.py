# -*- coding: utf-8 -*-
"""
sanctions.py
Chế tài của IPS:
  - Điểm vi phạm: mỗi lần vi phạm +1 điểm, đủ DIEM_DE_KHOA điểm trong THOI_HAN_DIEM thì khoá IP.
  - Khoá IP theo bậc: tái phạm khoá lâu hơn (BAC_KHOA).
  - Chế độ khẩn cấp DDoS: chỉ "IP quen" được vào, IP lạ nhận 429.
Các hàm ở đây được gọi khi đang giữ storage.LOCK.
"""

from . import config, storage

_diem = {}          # ip -> [thời điểm các lần vi phạm còn hiệu lực]
_khoa = {}          # ip -> {"het_han", "tu", "ly_do", "lan"}
_so_lan_khoa = {}   # ip -> đã bị khoá bao nhiêu lần (để tính bậc)
_sach_dau = {}      # ip -> thời điểm request sạch (200) đầu tiên
_khan_cap = {"bat": False, "tu": None, "vuot_cuoi": None}


# ------------------------- Khoá IP -------------------------

def dang_bi_khoa(ip, now):
    """Trả về thông tin khoá nếu IP đang bị khoá, None nếu không (tự gỡ khoá đã hết hạn)."""
    k = _khoa.get(ip)
    if k and k["het_han"] <= now:
        del _khoa[ip]
        storage.canh_bao("thong_tin", f"IP {ip} hết thời gian khoá")
        return None
    return k


def khoa(ip, ly_do, now):
    """Khoá IP theo bậc. Trả về mô tả chế tài để hiển thị."""
    lan = _so_lan_khoa.get(ip, 0) + 1
    _so_lan_khoa[ip] = lan
    thoi_gian = config.BAC_KHOA[min(lan, len(config.BAC_KHOA)) - 1]
    _khoa[ip] = {"het_han": now + thoi_gian, "tu": now, "ly_do": ly_do, "lan": lan}
    _diem.pop(ip, None)
    mo_ta = f"Khoá IP {thoi_gian // 60} phút (lần {lan})"
    storage.canh_bao("nguy_hiem", f"{mo_ta}: {ip} · {ly_do}")
    return mo_ta


def mo_khoa(ip):
    if _khoa.pop(ip, None) is None:
        return False
    _diem.pop(ip, None)
    storage.canh_bao("thong_tin", f"Quản trị viên mở khoá IP {ip}")
    return True


def ds_khoa(now):
    for ip in [ip for ip, k in _khoa.items() if k["het_han"] <= now]:
        dang_bi_khoa(ip, now)
    return [dict(ip=ip, **k) for ip, k in sorted(_khoa.items(), key=lambda x: -x[1]["tu"])]


# ------------------------- Điểm vi phạm -------------------------

def diem_hien_tai(ip, now):
    con = [t for t in _diem.get(ip, []) if now - t <= config.THOI_HAN_DIEM]
    if con:
        _diem[ip] = con
    else:
        _diem.pop(ip, None)
    return len(con)


def cong_diem(ip, ly_do, now):
    """+1 điểm vi phạm; đủ điểm thì khoá. Trả về mô tả chế tài."""
    so = diem_hien_tai(ip, now) + 1
    _diem.setdefault(ip, []).append(now)
    if so >= config.DIEM_DE_KHOA:
        return f"Đủ {so} điểm vi phạm → " + khoa(ip, ly_do, now)
    return f"+1 điểm vi phạm ({so}/{config.DIEM_DE_KHOA})"


# ------------------------- Chế độ khẩn cấp DDoS -------------------------

def ghi_nhan_sach(ip, now):
    """Ghi nhớ lần đầu IP có request sạch: cơ sở để xét 'IP quen' khi khẩn cấp."""
    _sach_dau.setdefault(ip, now)


def la_ip_quen(ip):
    """IP quen = đã có request sạch sớm hơn lúc bật khẩn cấp ít nhất IP_QUEN_TRUOC giây.
    Bot lọt được vài request đầu đợt flood vì thế KHÔNG được tính là quen."""
    t = _sach_dau.get(ip)
    return t is not None and _khan_cap["tu"] is not None and \
        t <= _khan_cap["tu"] - config.IP_QUEN_TRUOC


def cap_nhat_khan_cap(vuot_nguong, now):
    """Bật khi vượt ngưỡng DDoS; tắt khi KHAN_CAP_TAT_SAU giây liên tiếp không còn vượt."""
    if vuot_nguong:
        _khan_cap["vuot_cuoi"] = now
        if not _khan_cap["bat"]:
            _khan_cap.update(bat=True, tu=now)
            storage.canh_bao("nguy_hiem", "BẬT chế độ khẩn cấp DDoS: chỉ IP quen được truy cập")
    elif _khan_cap["bat"] and now - _khan_cap["vuot_cuoi"] >= config.KHAN_CAP_TAT_SAU:
        _khan_cap.update(bat=False, tu=None)
        storage.canh_bao("thong_tin", "TẮT chế độ khẩn cấp DDoS: lưu lượng đã trở lại bình thường")


def khan_cap_dang_bat():
    return _khan_cap["bat"]


def trang_thai_khan_cap():
    return {"bat": _khan_cap["bat"], "tu": _khan_cap["tu"]}


def xoa_het():
    for d in (_diem, _khoa, _so_lan_khoa, _sach_dau):
        d.clear()
    _khan_cap.update(bat=False, tu=None, vuot_cuoi=None)
