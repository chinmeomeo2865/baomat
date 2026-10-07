# -*- coding: utf-8 -*-
"""
server.py  --  SERVER GIÁM SÁT REALTIME
Server này đóng vai "web cần bảo vệ": nó nhận MỌI request gửi tới
(từ Postman, trình duyệt, curl...), phân loại ngay lập tức, rồi hiển thị
sống lên dashboard (tự cập nhật mỗi 1.5 giây).

Cách dùng:
    python3 server.py
  - Dashboard giám sát:  http://127.0.0.1:5000/__monitor
  - Bắn request để test: gửi tới http://127.0.0.1:5000/<bất kỳ đường dẫn nào>

Mẹo demo:
  - Nội dung tấn công (SQLi, XSS): chỉ cần 1 request là hiện ngay.
      vd: http://127.0.0.1:5000/product?id=1' OR '1'='1
  - DoS/DDoS (theo số lượng): chạy  python3 attack_demo.py  để bắn hàng loạt.
  - Giả lập nhiều IP khác nhau: đặt header  X-Forwarded-For: <ip>
"""

import sys
import time
import threading
from collections import deque
from datetime import datetime
from functools import wraps
from urllib.parse import unquote

from flask import Flask, request, jsonify, render_template_string

import detect

app = Flask(__name__)
# Body lớn hơn 1 MB bị Flask từ chối luôn (413), nên body nào lọt vào đều được quét toàn bộ
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024

# ------- Bộ nhớ lưu request gần đây (sống trong RAM) -------
REQUESTS = deque(maxlen=1000)   # các request gần nhất
LOCK = threading.Lock()
TONG = 0                        # tổng request từ lúc chạy
_ID = 0

# ------- Ngưỡng cho DoS/DDoS kiểu REALTIME (cửa sổ 10 giây) -------
# Để thấp cho dễ demo bằng tay / script nhỏ.
CUA_SO = 10          # xét trong 10 giây gần nhất
DOS_RT = 15          # 1 IP gửi > 15 request / 10s  => DoS
DDOS_TONG_RT = 40    # tổng > 40 request / 10s ...
DDOS_IP_RT = 8       # ... và từ > 8 IP khác nhau    => DDoS

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Máy chạy server. Chỉ tin X-Forwarded-For khi request đến từ đây (coi như proxy
# tin cậy), và chỉ cho phép thao tác quản trị từ đây.
MAY_TIN_CAY = ("127.0.0.1", "::1")

# Mọi request được ghi thêm ra file theo định dạng Combined Log Format (giống Nginx)
# -> tắt server không mất log, và phân tích lại được: python monitor.py realtime_access.log
FILE_LOG = "realtime_access.log"


# ------- CẤU HÌNH CHẾ ĐỘ PHÒNG THỦ (IPS / IDS) -------
CHE_DO_IPS = True   # True: IPS (Chặn đứng tấn công với mã 403/429)
                    # False: IDS (Chỉ giám sát và ghi log, trả mã 200)

def lay_ip():
    """
    Lấy IP client. Nếu request đến từ máy tin cậy (attack_demo.py, Postman trên
    cùng máy) thì dùng X-Forwarded-For để giả lập nhiều IP khi demo.
    Request từ máy khác thì luôn dùng IP kết nối thật: kẻ tấn công không thể
    đổi X-Forwarded-For liên tục để né luật DoS.
    """
    ip_that = request.remote_addr or "?"
    xff = request.headers.get("X-Forwarded-For")
    if xff and ip_that in MAY_TIN_CAY:
        return xff.split(",")[0].strip()
    return ip_that


def phan_loai(ip, e):
    """Chạy luật phát hiện cho 1 request vừa tới. Trả về (loai_list, nguy, ly_do)."""
    # 1) Luật theo NỘI DUNG (SQLi, XSS, công cụ quét, dò đường dẫn)
    nhan = detect.kiem_tra_request(e)

    # 2) Luật theo SỐ LƯỢNG (DoS, DDoS) - tính trên cửa sổ 10 giây
    now = time.time()
    gan_day = [r for r in REQUESTS if now - r["ts"] <= CUA_SO]

    cung_ip = sum(1 for r in gan_day if r["ip"] == ip) + 1   # +1: tính cả request này
    if cung_ip > DOS_RT:
        nhan.append(("DoS", "CAO", f"IP gửi {cung_ip} request trong {CUA_SO}s"))

    tong_cs = len(gan_day) + 1
    so_ip = len(set([r["ip"] for r in gan_day] + [ip]))
    if tong_cs > DDOS_TONG_RT and so_ip > DDOS_IP_RT:
        nhan.append(("DDoS", "CAO", f"{tong_cs} request từ {so_ip} IP trong {CUA_SO}s"))

    # Chuẩn hoá nhãn + mức độ
    def chuan(x):
        return "Công cụ quét" if x.startswith("Công cụ quét") else x

    loai = sorted(set(chuan(n[0]) for n in nhan))
    if any(n[1] == "CAO" for n in nhan):
        nguy = "CAO"
    elif nhan:
        nguy = "TB"
    else:
        nguy = "OK"
    ly_do = "; ".join(f"{n[0]} -> {n[2]}" for n in nhan)
    return (loai if loai else ["Bình thường"]), nguy, ly_do


def ghi_nhan():
    """Ghi lại request hiện tại vào bộ nhớ và phân loại."""
    global TONG, _ID

    ip = lay_ip()
    method = request.method
    duong_dan = request.full_path.rstrip("?")
    body = request.get_data(as_text=True)      # quét TOÀN BỘ body, không cắt
    agent = request.headers.get("User-Agent", "")

    # SQLi/XSS có thể nằm ở URL, body, Cookie, Referer hoặc User-Agent
    e = {
        "url": unquote(duong_dan), "body": body, "agent": agent,
        "referer": request.headers.get("Referer", ""),
        "cookie": request.headers.get("Cookie", ""),
    }
    loai, nguy, ly_do = phan_loai(ip, e)

    # Quyết định mã trạng thái HTTP theo chế độ IPS
    if CHE_DO_IPS and nguy != "OK":
        if "DoS" in loai or "DDoS" in loai:
            status = 429   # Too Many Requests (từ chối do DoS/DDoS)
        else:
            status = 403   # Forbidden (chặn SQLi, XSS, Scanner, Dò đường dẫn)
    else:
        status = 200       # Cho phép qua

    with LOCK:
        TONG += 1
        _ID += 1
        REQUESTS.append({
            "id": _ID,
            "ts": time.time(),
            "tg": datetime.now().strftime("%H:%M:%S"),
            "ip": ip,
            "method": method,
            "url": duong_dan,
            "agent": agent,
            "body": body[:1000],                # chỉ lưu 1000 ký tự đầu để hiển thị
            "status": status,
            "loai": loai,
            "nguy": nguy,
            "ly_do": ly_do,
        })
        ghi_file_log(ip, method, e["url"], status, e["referer"], agent)
    return loai, nguy, status, ly_do


def ghi_file_log(ip, method, url, status, referer, agent):
    """Ghi 1 dòng Combined Log Format ra FILE_LOG (gọi khi đang giữ LOCK)."""
    # Mã hoá ký tự làm hỏng dòng log (dấu ", xuống dòng, khoảng trắng trong URL).
    # URL dùng %xx để detect.py giải mã lại được đúng payload gốc.
    for k, v in (("%", "%25"), ('"', "%22"), ("\n", "%0A"), ("\r", "%0D"), (" ", "%20")):
        url = url.replace(k, v)
    def tho(s):
        return s.replace('"', "\\x22").replace("\n", "\\x0A").replace("\r", "\\x0D")
    tg = datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
    dong = (f'{ip} - - [{tg}] "{method} {url} HTTP/1.1" {status} - '
            f'"{tho(referer or "-")}" "{tho(agent)}"\n')
    try:
        with open(FILE_LOG, "a", encoding="utf-8") as f:
            f.write(dong)
    except OSError:
        pass   # lỗi ghi file không được làm sập IPS


# =========================================================
# ROUTE CHO DASHBOARD GIÁM SÁT (không bị tính là traffic)
# =========================================================

@app.route("/__data")
def du_lieu():
    """Trả JSON cho dashboard (được gọi lại mỗi 1.5 giây)."""
    with LOCK:
        ds = list(REQUESTS)

    # Thống kê
    by = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    for r in ds:
        by[f"{r['status'] // 100}xx"] = by.get(f"{r['status'] // 100}xx", 0) + 1
    so_ip = len(set(r["ip"] for r in ds))
    so_canh_bao = sum(1 for r in ds if r["nguy"] != "OK")

    # Biểu đồ: số request mỗi 2 giây trong 60 giây gần nhất
    now = time.time()
    buckets = {}
    for i in range(30):
        buckets[i] = 0
    for r in ds:
        d = now - r["ts"]
        if d <= 60:
            buckets[int(d // 2)] += 1
    labels = [f"-{i*2}s" for i in range(29, -1, -1)]
    data = [buckets[i] for i in range(29, -1, -1)]

    # Danh sách request mới nhất lên đầu (tối đa 200 dòng)
    rows = list(reversed(ds))[:200]

    return jsonify({
        "tong": TONG, "by": by, "so_ip": so_ip, "so_canh_bao": so_canh_bao,
        "ips_mode": CHE_DO_IPS,
        "chart_labels": labels, "chart_data": data, "rows": rows,
    })


def chi_quan_tri(f):
    """
    Chỉ cho phép thao tác quản trị (tắt IPS, xoá log) khi:
      - request đến từ chính máy chạy server (127.0.0.1 / ::1). Dùng
        remote_addr thật, KHÔNG dùng X-Forwarded-For vì header đó giả mạo được;
      - có header X-IPS-Admin. Form/thẻ <img> từ trang web khác không tự
        gắn được header này, nên chống được tấn công CSRF.
    """
    @wraps(f)
    def boc(*args, **kwargs):
        if request.remote_addr not in MAY_TIN_CAY or \
                request.headers.get("X-IPS-Admin") != "1":
            return jsonify({"loi": "Không có quyền quản trị IPS"}), 403
        return f(*args, **kwargs)
    return boc


@app.route("/__toggle_mode", methods=["POST"])
@chi_quan_tri
def toggle_mode():
    """Bật/tắt chế độ IPS (Chặn) và IDS (Chỉ giám sát)."""
    global CHE_DO_IPS
    CHE_DO_IPS = not CHE_DO_IPS
    return jsonify({"ips": CHE_DO_IPS})


@app.route("/__reset", methods=["POST"])
@chi_quan_tri
def reset():
    """Xoá hết log đang hiển thị (để demo lại từ đầu)."""
    global TONG
    with LOCK:
        REQUESTS.clear()
        TONG = 0
    return jsonify({"ok": True})


@app.route("/__monitor")
def monitor():
    return render_template_string(
        HTML, cua_so=CUA_SO, dos=DOS_RT, ddos_tong=DDOS_TONG_RT, ddos_ip=DDOS_IP_RT,
    )


# =========================================================
# CATCH-ALL: bắt MỌI request khác -> đây là traffic cần kiểm tra
# =========================================================

@app.route("/", defaults={"p": ""}, methods=METHODS)
@app.route("/<path:p>", methods=METHODS)
def bat_request(p):
    if p == "favicon.ico":
        return ("", 204)
    loai, nguy, status, ly_do = ghi_nhan()
    
    # NẾU Ở CHẾ ĐỘ IPS VÀ BỊ CHẶN:
    if status == 403:
        return jsonify({
            "trang_thai": "BLOCKED",
            "he_thong": "IPS / WAF Active Defense",
            "thong_bao": "Yêu cầu bị từ chối truy cập (403 Forbidden)",
            "phan_loai": loai,
            "ly_do": ly_do,
        }), 403
    elif status == 429:
        return jsonify({
            "trang_thai": "RATE_LIMITED",
            "he_thong": "IPS / WAF Active Defense",
            "thong_bao": "Yêu cầu bị từ chối do vượt quá tần suất (429 Too Many Requests)",
            "phan_loai": loai,
            "ly_do": ly_do,
        }), 429

    return jsonify({
        "thong_bao": "Server đã tiếp nhận request hợp lệ",
        "phan_loai": loai,
        "muc_do": nguy,
    }), 200


# =========================================================
# GIAO DIỆN DASHBOARD (tự cập nhật bằng JavaScript)
# =========================================================

HTML = r"""
<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hệ thống giám sát &amp; ngăn chặn tấn công web (IPS)</title>
<script src="/static/chart.umd.min.js"></script>  <!-- Chart.js lưu sẵn trong static/: demo không cần Internet -->
<style>
  * { box-sizing: border-box; }
  body { font-family: Arial, sans-serif; margin:0; background:#f1f5f9; color:#1f2937; }
  header { background:#111827; color:#fff; padding:14px 24px; display:flex;
           justify-content:space-between; align-items:center; }
  header h1 { margin:0; font-size:18px; }
  .live { font-size:13px; background:#16a34a; padding:4px 12px; border-radius:20px; }
  .live.off { background:#9ca3af; }
  .tabs { display:flex; gap:8px; padding:12px 24px 0; background:#111827; }
  .tab { padding:9px 18px; border-radius:8px 8px 0 0; cursor:pointer; color:#cbd5e1;
         background:#1f2937; font-size:14px; }
  .tab.active { background:#f1f5f9; color:#111827; font-weight:bold; }
  .wrap { padding:22px 24px; max-width:1200px; margin:auto; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:18px; }
  .card { background:#fff; border-radius:10px; padding:14px 18px; flex:1; min-width:110px;
          box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .card .num { font-size:24px; font-weight:bold; }
  .card .lbl { color:#6b7280; font-size:12px; margin-top:2px; }
  .c2 { color:#16a34a; } .c3 { color:#0891b2; } .c4 { color:#dc2626; }
  .c5 { color:#dc2626; } .cr { color:#dc2626; }
  .box { background:#fff; border-radius:10px; padding:18px; margin-bottom:18px;
         box-shadow:0 1px 3px rgba(0,0,0,.08); }
  h2 { font-size:15px; margin:0 0 12px; }
  .filters { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  select, input, button { padding:8px 10px; border:1px solid #d1d5db; border-radius:7px; font-size:13px; }
  button { cursor:pointer; background:#f3f4f6; }
  input { min-width:180px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:7px 9px; border-bottom:1px solid #eee; }
  th { background:#f9fafb; position:sticky; top:0; }
  tbody tr { cursor:pointer; }
  tbody tr:hover { background:#f8fafc; }
  tbody tr.moi { animation: hl 1.2s ease-out; }
  @keyframes hl { from { background:#fef08a; } to { background:transparent; } }
  .st { font-weight:bold; padding:2px 8px; border-radius:6px; color:#fff; font-size:12px; }
  .s2 { background:#16a34a; } .s3 { background:#0891b2; }
  .s4 { background:#dc2626; } .s5 { background:#dc2626; }
  .badge { padding:2px 8px; border-radius:12px; font-size:11px; color:#fff; margin-right:3px;
           display:inline-block; }
  .bCAO { background:#dc2626; } .bTB { background:#f59e0b; } .bOK { background:#9ca3af; }
  .tbl-scroll { max-height:460px; overflow:auto; }
  .muted { color:#9ca3af; font-size:12px; }
  .overlay { position:fixed; inset:0; background:rgba(0,0,0,.5); display:none;
             align-items:center; justify-content:center; padding:20px; z-index:50; }
  .modal { background:#fff; border-radius:12px; padding:22px; max-width:640px; width:100%;
           max-height:85vh; overflow:auto; }
  .kv { display:grid; grid-template-columns:150px 1fr; gap:6px 12px; font-size:13px; }
  .kv b { color:#6b7280; font-weight:normal; }
  .kv span { word-break:break-all; }
  .close { float:right; cursor:pointer; color:#9ca3af; font-size:20px; }
  .doc table td { vertical-align:top; }
  .doc code { background:#f3f4f6; padding:1px 5px; border-radius:4px; }
  .page { display:none; } .page.active { display:block; }
  .hint { background:#eff6ff; border:1px solid #bfdbfe; border-radius:8px; padding:10px 14px;
          font-size:13px; margin-bottom:16px; }
  .hint code { background:#dbeafe; padding:1px 5px; border-radius:4px; }
</style>
</head>
<body>
<header>
  <h1>Hệ thống giám sát &amp; ngăn chặn tấn công web (IPS / WAF)</h1>
  <div style="display:flex;align-items:center;gap:12px;">
    <button id="btnMode" onclick="doiCheDo()" style="font-weight:bold;padding:6px 14px;border-radius:20px;border:none;cursor:pointer;background:#dc2626;color:#fff;transition:0.2s;">
      🛡️ Chế độ: IPS (ĐANG CHẶN)
    </button>
    <span class="live" id="live">● Đang nhận dữ liệu trực tiếp</span>
  </div>
</header>
<div class="tabs">
  <div class="tab active" onclick="moTab('giamsat', this)">Giám sát &amp; Phòng thủ</div>
  <div class="tab" onclick="moTab('tailieu', this)">Tài liệu kỹ thuật</div>
</div>

<!-- TAB GIÁM SÁT -->
<div class="wrap page active" id="giamsat">
  <div class="hint">
    <b>Chế độ IPS đang kích hoạt:</b> Mọi request tấn công (SQLi, XSS, Scanner, Dò đường dẫn) sẽ bị <b>chặn đứng với mã 403 Forbidden</b>.
    Tấn công DoS/DDoS sẽ bị <b>chặn với mã 429 Too Many Requests</b>.
    (Bạn có thể bấm nút góc trên bên phải để chuyển qua lại giữa <b>IPS (Chặn)</b> và <b>IDS (Chỉ giám sát)</b>).
  </div>

  <div class="cards">
    <div class="card"><div class="num" id="tong">0</div><div class="lbl">Tổng request</div></div>
    <div class="card"><div class="num c2" id="n2">0</div><div class="lbl">2xx Cho phép qua</div></div>
    <div class="card"><div class="num c4" id="n4">0</div><div class="lbl">4xx Bị chặn (IPS)</div></div>
    <div class="card"><div class="num c5" id="n5">0</div><div class="lbl">5xx Lỗi server</div></div>
    <div class="card"><div class="num" id="soip">0</div><div class="lbl">Số IP khác nhau</div></div>
    <div class="card"><div class="num cr" id="canhbao">0</div><div class="lbl">Đã phát hiện &amp; chặn</div></div>
  </div>

  <div class="box">
    <h2>Lưu lượng request (60 giây gần nhất)</h2>
    <canvas id="bd" height="70"></canvas>
  </div>

  <div class="box">
    <h2>Nhật ký request (trực tiếp)</h2>
    <div class="filters">
      <label>Mã:
        <select id="fStatus" onchange="ve()">
          <option value="all">Tất cả</option>
          <option value="2xx">2xx (Hợp lệ)</option>
          <option value="4xx">4xx (Bị chặn)</option>
          <option value="5xx">5xx (Lỗi server)</option>
        </select>
      </label>
      <label>Phân loại:
        <select id="fLoai" onchange="ve()">
          <option value="all">Tất cả</option>
          <option value="Bình thường">Bình thường</option>
          <option value="SQL Injection">SQL Injection</option>
          <option value="XSS">XSS</option>
          <option value="Công cụ quét">Công cụ quét</option>
          <option value="Dò tìm đường dẫn nhạy cảm">Dò tìm đường dẫn</option>
          <option value="DoS">DoS</option>
          <option value="DDoS">DDoS</option>
        </select>
      </label>
      <input id="fTim" oninput="ve()" placeholder="Tìm theo IP hoặc URL...">
      <button onclick="reset()">Xoá log demo</button>
      <span class="muted" id="demKq"></span>
    </div>
    <div class="tbl-scroll" style="margin-top:12px;">
      <table>
        <thead><tr><th>Thời gian</th><th>IP</th><th>Method</th><th>URL</th><th>Mã</th><th>Phân loại</th></tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- TAB TÀI LIỆU -->
<div class="wrap page doc" id="tailieu">
  <div class="box">
    <h2>1. Ý nghĩa các mã trạng thái HTTP trong hệ thống IPS</h2>
    <table>
      <tr><th>Mã</th><th>Ý nghĩa</th><th>Liên quan bảo mật</th></tr>
      <tr><td><code>200</code></td><td>Thành công</td><td>Request hợp lệ, IPS cho phép đi vào ứng dụng</td></tr>
      <tr><td><code>403</code></td><td>Bị cấm (Forbidden)</td><td><b>Bị IPS CHẶN</b>: phát hiện SQL Injection, XSS, Scanner, File nhạy cảm</td></tr>
      <tr><td><code>429</code></td><td>Quá nhiều yêu cầu</td><td><b>Bị IPS CHẶN</b>: phát hiện DoS hoặc DDoS (Rate Limit)</td></tr>
      <tr><td><code>400</code></td><td>Request sai cú pháp</td><td>Payload tấn công bị dị dạng</td></tr>
      <tr><td><code>404</code></td><td>Không tìm thấy</td><td>Dò tìm đường dẫn không tồn tại</td></tr>
      <tr><td><code>500</code></td><td>Lỗi server</td><td>Lỗi mã nguồn hoặc SQL Injection khai thác sâu</td></tr>
      <tr><td><code>503</code></td><td>Quá tải</td><td>Hệ thống server bị kiệt quệ tài nguyên</td></tr>
    </table>
  </div>
  <div class="box">
    <h2>2. Cách phân biệt các loại tấn công</h2>
    <table>
      <tr><th>Loại</th><th>Dựa vào đâu để nhận biết</th><th>Hành vi xử lý của IPS</th></tr>
      <tr><td><b>DoS</b></td><td>1 IP gửi quá nhiều request trong {{ cua_so }}s (ngưỡng {{ dos }})</td><td>Chặn tức thì với mã <code>429 Too Many Requests</code></td></tr>
      <tr><td><b>DDoS</b></td><td>Tổng tăng vọt + nhiều IP (&gt;{{ ddos_tong }} req &amp; &gt;{{ ddos_ip }} IP /{{ cua_so }}s)</td><td>Chặn phân tán với mã <code>429 Too Many Requests</code></td></tr>
      <tr><td><b>SQL Injection</b></td><td>URL/body chứa cú pháp SQL (<code>' OR 1=1</code>, <code>UNION SELECT</code>)</td><td>Chặn tức thì với mã <code>403 Forbidden</code></td></tr>
      <tr><td><b>XSS</b></td><td>URL/body chứa thẻ HTML/JS (<code>&lt;script&gt;</code>, <code>onerror=</code>)</td><td>Chặn tức thì với mã <code>403 Forbidden</code></td></tr>
      <tr><td><b>Công cụ quét</b></td><td>User-Agent định danh các tool (<code>sqlmap</code>, <code>nikto</code>...)</td><td>Chặn tức thì với mã <code>403 Forbidden</code></td></tr>
      <tr><td><b>Dò tìm đường dẫn</b></td><td>Truy cập file nhạy cảm (<code>/.env</code>, <code>/wp-admin</code>...)</td><td>Chặn tức thì với mã <code>403 Forbidden</code></td></tr>
    </table>
  </div>
</div>

<div class="overlay" id="overlay" onclick="if(event.target.id==='overlay')dong()">
  <div class="modal">
    <span class="close" onclick="dong()">&times;</span>
    <h3>Chi tiết request</h3>
    <div class="kv" id="ctiet"></div>
  </div>
</div>

<script>
let DATA = [];
let bietId = 0;
const NHAN_MA = {
  200:"200 OK (Hợp lệ, được phép qua)",
  403:"403 Forbidden (BỊ IPS CHẶN: Nội dung độc hại / Quét)",
  429:"429 Too Many Requests (BỊ IPS CHẶN: DoS / DDoS)",
  404:"404 Not Found",
  500:"500 Lỗi server",
  503:"503 Quá tải"
};

let chart;
function taoChart(){
  if (typeof Chart === 'undefined') return;   // thiếu Chart.js thì bỏ biểu đồ, bảng vẫn chạy
  chart = new Chart(document.getElementById('bd'), {
    type:'line',
    data:{ labels:[], datasets:[{label:'Request', data:[], borderColor:'#2563eb',
           backgroundColor:'rgba(37,99,235,.1)', fill:true, tension:.3}] },
    options:{ animation:false, plugins:{legend:{display:false}},
              scales:{y:{beginAtZero:true}} }
  });
}

function badge(r){
  const cls = r.nguy==='CAO'?'bCAO':(r.nguy==='TB'?'bTB':'bOK');
  return r.loai.map(x=>'<span class="badge '+cls+'">'+x+'</span>').join('');
}

function ve(){
  const s=document.getElementById('fStatus').value;
  const l=document.getElementById('fLoai').value;
  const t=document.getElementById('fTim').value.toLowerCase();
  const kq=DATA.filter(r=>
    (s==='all'||(''+r.status).startsWith(s[0])) &&
    (l==='all'||r.loai.includes(l)) &&
    (t===''||r.ip.toLowerCase().includes(t)||r.url.toLowerCase().includes(t))
  );
  document.getElementById('tbody').innerHTML = kq.map(r=>
    '<tr class="'+(r.id>bietId?'moi':'')+'" onclick="xem('+r.id+')">'
    +'<td>'+r.tg+'</td><td>'+r.ip+'</td><td>'+r.method+'</td>'
    +'<td style="max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(r.url)+'</td>'
    +'<td><span class="st s'+(''+r.status)[0]+'">'+r.status+'</span></td>'
    +'<td>'+badge(r)+'</td></tr>'
  ).join('');
  document.getElementById('demKq').textContent='Hiển thị '+kq.length+'/'+DATA.length+' request';
}

function esc(s){ return (s+'').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function xem(id){
  const r=DATA.find(x=>x.id===id); if(!r) return;
  const ten=NHAN_MA[r.status]||('Mã '+r.status);
  document.getElementById('ctiet').innerHTML=
     '<b>Thời gian</b><span>'+r.tg+'</span>'
    +'<b>Địa chỉ IP</b><span>'+r.ip+'</span>'
    +'<b>Method</b><span>'+r.method+'</span>'
    +'<b>URL</b><span>'+esc(r.url)+'</span>'
    +'<b>Body</b><span>'+esc(r.body||'(trống)')+'</span>'
    +'<b>Mã trạng thái</b><span>'+r.status+' - '+ten+'</span>'
    +'<b>User-Agent</b><span>'+esc(r.agent)+'</span>'
    +'<b>Phân loại</b><span>'+r.loai.join(', ')+' (mức độ: '+r.nguy+')</span>'
    +'<b>Hành vi IPS</b><span>'+(r.status>=400 ? '⛔ ĐÃ BỊ TỪ CHỐI / CHẶN TẠI CỬA' : '✅ ĐÃ CHO PHÉP TRUY CẬP')+'</span>'
    +'<b>Lý do đánh dấu</b><span>'+esc(r.ly_do||'Không có dấu hiệu tấn công')+'</span>';
  document.getElementById('overlay').style.display='flex';
}
function dong(){ document.getElementById('overlay').style.display='none'; }
function moTab(id,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById(id).classList.add('active'); el.classList.add('active');
}
// Thao tác quản trị: bắt buộc POST + header X-IPS-Admin (xem chi_quan_tri trong server.py)
const QUAN_TRI = {method:'POST', headers:{'X-IPS-Admin':'1'}};
async function reset(){ await fetch('/__reset', QUAN_TRI); bietId=0; capNhat(); }

async function doiCheDo(){
  const r=await fetch('/__toggle_mode', QUAN_TRI);
  if(!r.ok){ alert('Không có quyền đổi chế độ (chỉ thao tác được trên máy chạy server)'); return; }
  const d=await r.json();
  capNhatNutMode(d.ips);
  capNhat();
}

function capNhatNutMode(isIps){
  const btn=document.getElementById('btnMode');
  if(!btn) return;
  if(isIps){
    btn.style.background='#dc2626';
    btn.textContent='🛡️ Chế độ: IPS (ĐANG CHẶN)';
  } else {
    btn.style.background='#d97706';
    btn.textContent='👁️ Chế độ: IDS (CHỈ GIÁM SÁT)';
  }
}

async function capNhat(){
  try{
    const r=await fetch('/__data'); const d=await r.json();
    document.getElementById('live').classList.remove('off');
    document.getElementById('live').textContent='● Đang nhận dữ liệu trực tiếp';
    document.getElementById('tong').textContent=d.tong;
    document.getElementById('n2').textContent=d.by['2xx']||0;
    document.getElementById('n4').textContent=d.by['4xx']||0;
    document.getElementById('n5').textContent=d.by['5xx']||0;
    document.getElementById('soip').textContent=d.so_ip;
    document.getElementById('canhbao').textContent=d.so_canh_bao;
    capNhatNutMode(d.ips_mode);
    if(chart){ chart.data.labels=d.chart_labels; chart.data.datasets[0].data=d.chart_data; chart.update(); }
    const maxId = d.rows.length ? Math.max(...d.rows.map(x=>x.id)) : bietId;
    DATA=d.rows; ve(); bietId=maxId;
  }catch(e){
    document.getElementById('live').classList.add('off');
    document.getElementById('live').textContent='● Mất kết nối server';
  }
}

taoChart();
capNhat();
setInterval(capNhat, 1500);   // tự cập nhật mỗi 1.5 giây
</script>
</body>
</html>
"""


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")   # tránh lỗi in tiếng Việt trên terminal Windows
    print("=" * 55)
    print(" SERVER GIÁM SÁT REALTIME đang chạy")
    print(" Dashboard:  http://127.0.0.1:5000/__monitor")
    print(" Bắn request test tới: http://127.0.0.1:5000/...")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, threaded=True)
