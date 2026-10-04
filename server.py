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

import time
import threading
from collections import deque
from datetime import datetime
from urllib.parse import unquote

from flask import Flask, request, jsonify, render_template_string

import detect

app = Flask(__name__)

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


def lay_ip():
    """Lấy IP client. Ưu tiên X-Forwarded-For (để demo giả lập nhiều IP)."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "?"


def phan_loai(ip, url_full, agent):
    """Chạy luật phát hiện cho 1 request vừa tới. Trả về (loai_list, nguy, ly_do)."""
    # 1) Luật theo NỘI DUNG (SQLi, XSS, công cụ quét, dò đường dẫn)
    e = {"url": url_full, "agent": agent, "ip": ip, "status": 200}
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
    # Gộp đường dẫn + query + body để quét (SQLi/XSS có thể nằm ở body)
    duong_dan = request.full_path.rstrip("?")
    body = request.get_data(as_text=True)[:1000]
    url_quet = unquote(duong_dan) + (" " + body if body else "")
    agent = request.headers.get("User-Agent", "")

    loai, nguy, ly_do = phan_loai(ip, url_quet, agent)

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
            "body": body,
            "status": 200,
            "loai": loai,
            "nguy": nguy,
            "ly_do": ly_do,
        })
    return loai, nguy


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
        "chart_labels": labels, "chart_data": data, "rows": rows,
    })


@app.route("/__reset")
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
    loai, nguy = ghi_nhan()
    return jsonify({
        "thong_bao": "Server đã nhận request",
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
<title>Giám sát tấn công web (Realtime)</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
  .c2 { color:#16a34a; } .c3 { color:#0891b2; } .c4 { color:#d97706; }
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
  .st { font-weight:bold; padding:1px 7px; border-radius:6px; color:#fff; font-size:12px; }
  .s2 { background:#16a34a; } .s3 { background:#0891b2; }
  .s4 { background:#d97706; } .s5 { background:#dc2626; }
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
  <h1>Hệ thống giám sát &amp; phát hiện tấn công web — REALTIME</h1>
  <span class="live" id="live">● Đang nhận dữ liệu trực tiếp</span>
</header>
<div class="tabs">
  <div class="tab active" onclick="moTab('giamsat', this)">Giám sát</div>
  <div class="tab" onclick="moTab('tailieu', this)">Tài liệu kỹ thuật</div>
</div>

<!-- TAB GIÁM SÁT -->
<div class="wrap page active" id="giamsat">
  <div class="hint">
    Gửi thử request tới server để xem nó hiện lên ngay:
    <code>http://127.0.0.1:5000/product?id=1' OR '1'='1</code> (SQLi) ·
    <code>/comment?text=&lt;script&gt;</code> (XSS) ·
    chạy <code>python3 attack_demo.py</code> để demo DoS/DDoS.
  </div>

  <div class="cards">
    <div class="card"><div class="num" id="tong">0</div><div class="lbl">Tổng request</div></div>
    <div class="card"><div class="num c2" id="n2">0</div><div class="lbl">2xx Thành công</div></div>
    <div class="card"><div class="num c4" id="n4">0</div><div class="lbl">4xx Lỗi client</div></div>
    <div class="card"><div class="num c5" id="n5">0</div><div class="lbl">5xx Lỗi server</div></div>
    <div class="card"><div class="num" id="soip">0</div><div class="lbl">Số IP khác nhau</div></div>
    <div class="card"><div class="num cr" id="canhbao">0</div><div class="lbl">Request nghi tấn công</div></div>
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
          <option value="2xx">2xx</option><option value="4xx">4xx</option><option value="5xx">5xx</option>
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
    <h2>1. Ý nghĩa các mã trạng thái HTTP</h2>
    <table>
      <tr><th>Mã</th><th>Ý nghĩa</th><th>Liên quan bảo mật</th></tr>
      <tr><td><code>200</code></td><td>Thành công</td><td>Bình thường</td></tr>
      <tr><td><code>301/302</code></td><td>Chuyển hướng</td><td>Bình thường</td></tr>
      <tr><td><code>400</code></td><td>Request sai cú pháp</td><td>Có thể do payload tấn công bị lỗi</td></tr>
      <tr><td><code>401</code></td><td>Chưa đăng nhập</td><td>Nhiều 401 = dò mật khẩu (brute-force)</td></tr>
      <tr><td><code>403</code></td><td>Bị cấm</td><td>Có thể đang dò quyền truy cập</td></tr>
      <tr><td><code>404</code></td><td>Không tìm thấy</td><td>Nhiều 404 từ 1 IP = đang quét</td></tr>
      <tr><td><code>429</code></td><td>Gửi quá nhiều</td><td>Dấu hiệu DoS</td></tr>
      <tr><td><code>500</code></td><td>Lỗi server</td><td>SQL Injection hay gây lỗi 500</td></tr>
      <tr><td><code>503</code></td><td>Quá tải</td><td>Dấu hiệu DDoS</td></tr>
    </table>
  </div>
  <div class="box">
    <h2>2. Cách phân biệt các loại tấn công</h2>
    <table>
      <tr><th>Loại</th><th>Dựa vào đâu để nhận biết</th><th>Ví dụ dấu hiệu</th></tr>
      <tr><td><b>DoS</b></td><td>1 IP gửi quá nhiều request trong {{ cua_so }}s (ngưỡng {{ dos }})</td><td>1 IP gửi 20 request/10s</td></tr>
      <tr><td><b>DDoS</b></td><td>Tổng tăng vọt + nhiều IP (&gt;{{ ddos_tong }} req &amp; &gt;{{ ddos_ip }} IP /{{ cua_so }}s)</td><td>60 request từ 30 IP</td></tr>
      <tr><td><b>SQL Injection</b></td><td>URL/body chứa cú pháp SQL</td><td><code>' OR 1=1</code>, <code>UNION SELECT</code>, <code>--</code></td></tr>
      <tr><td><b>XSS</b></td><td>URL/body chứa mã HTML/JS</td><td><code>&lt;script&gt;</code>, <code>onerror=</code></td></tr>
      <tr><td><b>Công cụ quét</b></td><td>User-Agent là tên công cụ tấn công</td><td><code>sqlmap</code>, <code>nikto</code></td></tr>
      <tr><td><b>Dò tìm đường dẫn</b></td><td>Truy cập đường dẫn quản trị/nhạy cảm</td><td><code>/wp-admin</code>, <code>/.env</code></td></tr>
    </table>
    <p class="muted">Phân biệt nhanh: tấn công <b>theo nội dung</b> (SQLi, XSS) nhìn URL;
    <b>theo số lượng</b> (DoS, DDoS) nhìn số request/giây; <b>thăm dò</b> (quét, dò đường dẫn) nhìn User-Agent và mã 404.</p>
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
let bietId = 0;          // id request mới nhất đã thấy (để tô sáng dòng mới)
const NHAN_MA = {200:"OK - thành công",403:"Forbidden - bị cấm",404:"Not Found",500:"Lỗi server (có thể do SQLi)",503:"Quá tải (nghi DDoS)"};

let chart;
function taoChart(){
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
    +'<b>Lý do đánh dấu</b><span>'+esc(r.ly_do||'Không có dấu hiệu tấn công')+'</span>';
  document.getElementById('overlay').style.display='flex';
}
function dong(){ document.getElementById('overlay').style.display='none'; }
function moTab(id,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById(id).classList.add('active'); el.classList.add('active');
}
async function reset(){ await fetch('/__reset'); bietId=0; capNhat(); }

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
    chart.data.labels=d.chart_labels; chart.data.datasets[0].data=d.chart_data; chart.update();
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
    print("=" * 55)
    print(" SERVER GIÁM SÁT REALTIME đang chạy")
    print(" Dashboard:  http://127.0.0.1:5000/__monitor")
    print(" Bắn request test tới: http://127.0.0.1:5000/...")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, threaded=True)
