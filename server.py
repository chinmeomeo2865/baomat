# -*- coding: utf-8 -*-
"""
server.py  --  IPS bảo vệ ứng dụng web
Mọi request gửi tới server đều đi qua pipeline của IPS (ips/engine.py): bị khoá thì
từ chối, vi phạm thì chặn 403/429 và chịu chế tài, sạch thì cho qua 200.

Cách dùng:
    python server.py
  - Giao diện giám sát: http://127.0.0.1:5000/__monitor
  - Bắn request để test: http://127.0.0.1:5000/<bất kỳ đường dẫn nào>
  - Giả lập nhiều IP (chỉ từ máy chạy server): header X-Forwarded-For: <ip>
"""

import sys
from functools import wraps

from flask import Flask, jsonify, render_template, request
from werkzeug.routing import PathConverter

from ips import config, engine, sanctions, storage
from ips.rules import CAC_LUAT


class MoiDuongDan(PathConverter):
    """Converter path mặc định không khớp ký tự xuống dòng: /a%0Ab sẽ thành 404 mà
    KHÔNG đi qua IPS. Converter này khớp mọi đường dẫn để không request nào lọt."""
    regex = "(?s:.*)"
    part_isolating = False   # khớp qua nhiều đoạn /a/b/c (werkzeug tự đặt True vì regex không chứa "/")


app = Flask(__name__)
app.url_map.converters["moi"] = MoiDuongDan
# Body lớn hơn 1 MB bị Flask từ chối luôn (413), nên body nào lọt vào đều được quét toàn bộ
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


def lay_ip():
    """
    IP client. Request từ máy chạy server (attack_demo.py, Postman) được dùng
    X-Forwarded-For để giả lập nhiều IP; máy khác luôn dùng IP kết nối thật,
    nên kẻ tấn công không đổi header này để né luật DoS hay né khoá IP được.
    """
    ip_that = request.remote_addr or "?"
    xff = request.headers.get("X-Forwarded-For")
    if xff and ip_that in config.MAY_TIN_CAY:
        return xff.split(",")[0].strip()
    return ip_that


def chi_quan_tri(f):
    """
    Thao tác quản trị (mở khoá IP, xoá dữ liệu) chỉ được phép khi:
      - request đến từ chính máy chạy server (remote_addr thật, không dùng XFF);
      - có header X-IPS-Admin: trang web khác không tự gắn được header này (chống CSRF).
    """
    @wraps(f)
    def boc(*args, **kwargs):
        if request.remote_addr not in config.MAY_TIN_CAY or \
                request.headers.get("X-IPS-Admin") != "1":
            return jsonify({"loi": "Không có quyền quản trị IPS"}), 403
        return f(*args, **kwargs)
    return boc


# =========================================================
# GIAO DIỆN GIÁM SÁT (các route /__* không đi qua IPS)
# =========================================================

@app.route("/__monitor")
def monitor():
    return render_template("monitor.html")


@app.route("/__data")
def du_lieu():
    """Dữ liệu cho giao diện giám sát (gọi lại mỗi 1,5 giây)."""
    with storage.LOCK:
        now = storage.bay_gio()
        sanctions.cap_nhat_khan_cap(False, now)   # cho phép tắt khẩn cấp cả khi không còn request
        ds = storage.tat_ca()
        ds_khoa = sanctions.ds_khoa(now)
        canh_bao = storage.ds_canh_bao()
        khan_cap = sanctions.trang_thai_khan_cap()
        tong = storage.tong_request()

    theo_loai = {luat.MA: 0 for luat in CAC_LUAT}
    for r in ds:
        for x in r["loai"]:
            if x["ma"] in theo_loai:
                theo_loai[x["ma"]] += 1

    # Biểu đồ: số request mỗi 2 giây trong 60 giây gần nhất, chia theo kết quả
    nhom = {"cho_qua": [0] * 30, "chan_403": [0] * 30, "chan_429": [0] * 30}
    for r in ds:
        tuoi = now - r["ts"]
        if tuoi < 60:
            k = "chan_403" if r["ket_qua"] == "ip_bi_khoa" else r["ket_qua"]
            nhom[k][29 - int(tuoi // 2)] += 1

    return jsonify({
        "bay_gio": now,
        "tong": tong,
        "cho_qua": sum(1 for r in ds if r["status"] == 200),
        "bi_chan": sum(1 for r in ds if r["status"] != 200),
        "luat": [{"ma": l.MA, "ten": l.TEN} for l in CAC_LUAT],
        "theo_loai": theo_loai,
        "bieu_do": {"nhan": [f"-{(29 - i) * 2}s" for i in range(30)], **nhom},
        "ds_khoa": ds_khoa,
        "canh_bao": canh_bao[:50],
        "khan_cap": khan_cap,
        "rows": list(reversed(ds))[:300],
    })


@app.route("/__unban", methods=["POST"])
@chi_quan_tri
def unban():
    ip = (request.get_json(silent=True) or {}).get("ip", "")
    with storage.LOCK:
        ok = sanctions.mo_khoa(ip)
    return jsonify({"ok": ok})


@app.route("/__reset", methods=["POST"])
@chi_quan_tri
def reset():
    """Xoá lịch sử, cảnh báo, điểm vi phạm và danh sách khoá (để demo lại từ đầu)."""
    with storage.LOCK:
        storage.xoa_het()
        sanctions.xoa_het()
    return jsonify({"ok": True})


# =========================================================
# MỌI REQUEST KHÁC: traffic cần IPS kiểm tra
# =========================================================

THONG_BAO = {
    "cho_qua": "Request hợp lệ, đã được cho qua",
    "chan_403": "Yêu cầu bị IPS chặn (403 Forbidden)",
    "chan_429": "Yêu cầu bị IPS từ chối do vượt tần suất (429 Too Many Requests)",
    "ip_bi_khoa": "IP của bạn đang bị IPS khoá (403 Forbidden)",
}


@app.route("/", defaults={"p": ""}, methods=METHODS)
@app.route("/<moi:p>", methods=METHODS)
def bat_request(p):
    if p == "favicon.ico":
        return ("", 204)

    r = engine.xu_ly({
        "ip": lay_ip(),
        "method": request.method,
        "url": request.full_path.rstrip("?"),
        "body": request.get_data(as_text=True),      # quét TOÀN BỘ body
        "agent": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
        "cookie": request.headers.get("Cookie", ""),
    })

    noi_dung = {
        "trang_thai": r["ket_qua"],
        "thong_bao": THONG_BAO[r["ket_qua"]],
        "phan_loai": [x["ten"] for x in r["loai"]] or ["Bình thường"],
    }
    if r["status"] != 200:
        noi_dung["ly_do"] = "; ".join(f"{x['ten']} -> {x['chi_tiet']}" for x in r["loai"])
        noi_dung["che_tai"] = r["che_tai"]
    resp = jsonify(noi_dung)
    resp.status_code = r["status"]
    if r["status"] == 429:
        resp.headers["Retry-After"] = str(config.RETRY_AFTER)
    return resp


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")   # tránh lỗi in tiếng Việt trên terminal Windows
    print("=" * 55)
    print(" IPS đang chạy")
    print(" Giao diện giám sát: http://127.0.0.1:5000/__monitor")
    print(" Bắn request test tới: http://127.0.0.1:5000/...")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, threaded=True)
