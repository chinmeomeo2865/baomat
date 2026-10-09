# -*- coding: utf-8 -*-
"""
engine.py
Pipeline xử lý 1 request:

  1. IP đang bị khoá?            -> 403 ngay, không phân tích thêm
  2. Chạy 6 luật trong rules/     -> danh sách luật vi phạm
  3. Quyết định (theo thứ tự ưu tiên):
       DoS                        -> 429 + Retry-After, +1 điểm vi phạm
       khẩn cấp DDoS và IP lạ     -> 429, không tính điểm
       luật nội dung              -> 403, +1 điểm (công cụ quét: khoá ngay)
       sạch                       -> 200
  4. Ghi nhận: lịch sử, file log
"""

from . import config, sanctions, storage
from .rules import CAC_LUAT, base
from .rules import dos as luat_dos, ddos as luat_ddos


def xu_ly(req):
    """
    req: dict thô gồm ip, method, url, body, cookie, referer, agent.
    Trả về bản ghi đã lưu (status, loai, che_tai, ...).
    """
    now = storage.bay_gio()
    req = base.chuan_hoa(req)
    req["ts"] = now
    ip = req["ip"]

    with storage.LOCK:
        khoa = sanctions.dang_bi_khoa(ip, now)
        if khoa:
            quyet_dinh = {
                "status": 403, "ket_qua": "ip_bi_khoa",
                "loai": [{"ma": "ip_bi_khoa", "ten": "IP bị khoá", "muc_do": "CAO",
                          "chi_tiet": f"Khoá đến {storage.gio_dep(khoa['het_han'])} · {khoa['ly_do']}"}],
                "che_tai": "Từ chối: IP đang trong thời gian khoá", "ghi_chu": "",
            }
        else:
            lich_su = storage.trong_cua_so(now)
            vi_pham = [(luat, ct) for luat in CAC_LUAT if (ct := luat.kiem_tra(req, lich_su))]
            sanctions.cap_nhat_khan_cap(any(l is luat_ddos for l, _ in vi_pham), now)
            quyet_dinh = _quyet_dinh(ip, vi_pham, now)

        ban_ghi = {
            "ts": now, "tg": storage.gio_dep(now), "ip": ip, "method": req.get("method", "GET"),
            "url": req["url"], "body": req["body"][:1000], "agent": req["agent"],
            "referer": req["referer"], "cookie": req["cookie"][:300],
            "muc_do": _muc_do(quyet_dinh["loai"]),
            "diem": sanctions.diem_hien_tai(ip, now),
            **quyet_dinh,
        }
        return storage.them(ban_ghi)


def _nhan(luat, chi_tiet):
    return {"ma": luat.MA, "ten": luat.TEN, "muc_do": luat.MUC_DO, "chi_tiet": chi_tiet}


def _quyet_dinh(ip, vi_pham, now):
    dos = [(l, ct) for l, ct in vi_pham if l is luat_dos]
    ddos = [(l, ct) for l, ct in vi_pham if l is luat_ddos]
    noi_dung = [(l, ct) for l, ct in vi_pham if l.PHAN_HOI == 403]
    khan_cap = sanctions.khan_cap_dang_bat()

    if dos:
        luat_chan, status = dos + noi_dung, 429
    elif khan_cap and not sanctions.la_ip_quen(ip):
        # DDoS không phạt từng IP (bot đổi IP liên tục): chỉ từ chối IP lạ trong lúc khẩn cấp
        ct = ddos[0][1] if ddos else "Chế độ khẩn cấp đang bật: IP lạ bị từ chối"
        return {"status": 429, "ket_qua": "chan_429",
                "loai": [_nhan(luat_ddos, ct)] + [_nhan(l, c) for l, c in noi_dung],
                "che_tai": "Khẩn cấp DDoS: IP lạ bị từ chối (không tính điểm)", "ghi_chu": ""}
    elif noi_dung:
        luat_chan, status = noi_dung, 403
    else:
        sanctions.ghi_nhan_sach(ip, now)
        return {"status": 200, "ket_qua": "cho_qua", "loai": [], "che_tai": "",
                "ghi_chu": "Khẩn cấp DDoS đang bật: IP quen được cho qua" if khan_cap else ""}

    # Một request bị chặn chỉ chịu MỘT chế tài: khoá ngay (nếu có luật đòi) hoặc +1 điểm
    ten = ", ".join(l.TEN for l, _ in luat_chan)
    if any(l.CHE_TAI == config.KHOA_NGAY for l, _ in luat_chan):
        che_tai = sanctions.khoa(ip, ten, now)
    else:
        che_tai = sanctions.cong_diem(ip, ten, now)
    return {"status": status, "ket_qua": f"chan_{status}",
            "loai": [_nhan(l, ct) for l, ct in luat_chan], "che_tai": che_tai, "ghi_chu": ""}


def _muc_do(loai):
    if any(x["muc_do"] == "CAO" for x in loai):
        return "CAO"
    return "TB" if loai else "OK"
