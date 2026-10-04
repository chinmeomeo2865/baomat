# -*- coding: utf-8 -*-
"""
dashboard.py
He thong QUAN LY & giam sat log web.
  - Hien thi MOI request (ca thanh cong va loi), co phan loai ngay
  - Thong ke theo nhom ma: 2xx / 3xx / 4xx / 5xx
  - Loc theo ma trang thai, theo loai tan cong, tim theo IP
  - Click 1 request de xem chi tiet day du
  - Tab "Tai lieu ky thuat": y nghia ma HTTP + cach phan biet tan cong

Cach dung:
    python3 dashboard.py
    -> http://127.0.0.1:5000
"""

from collections import Counter, defaultdict
from urllib.parse import unquote
from flask import Flask, render_template_string

import parser
import detect

LOG_FILE = "access.log"
app = Flask(__name__)


def nhom_ma(status):
    """Phan nhom ma HTTP: 2xx thanh cong, 4xx loi phia client, ..."""
    return f"{status // 100}xx"


def chuan_hoa_loai(loai):
    """Gom nhan ve nhom chung de loc (vd 'Cong cu quet: sqlmap' -> 'Cong cu quet')."""
    if loai.startswith("Cong cu quet"):
        return "Cong cu quet"
    return loai


def xay_du_lieu(entries):
    """Tao danh sach request da duoc gan nhan, phuc vu bang + loc + chi tiet."""
    dos_ips = detect.ip_bi_dos(entries)
    ddos_phut = detect.phut_bi_ddos(entries)

    rows = []
    for e in entries:
        phut = e["dt"].strftime("%Y-%m-%d %H:%M") if e["dt"] else ""

        # Gan nhan cho tung request
        nhan = detect.kiem_tra_request(e)          # [(loai, muc, chi_tiet), ...]
        if e["ip"] in dos_ips:
            nhan.append(("DoS", "CAO", "IP gui qua nhieu request trong 1 phut"))
        if phut in ddos_phut:
            nhan.append(("DDoS", "CAO", "Request nam trong phut bi DDoS"))

        loai_list = sorted(set(chuan_hoa_loai(n[0]) for n in nhan))
        if any(n[1] == "CAO" for n in nhan):
            nguy = "CAO"
        elif nhan:
            nguy = "TB"
        else:
            nguy = "OK"

        rows.append({
            "tg": e["dt"].strftime("%H:%M:%S") if e["dt"] else "?",
            "ip": e["ip"],
            "method": e["method"],
            "url": e["url"],
            "url_giai_ma": unquote(e["url"]),
            "status": e["status"],
            "nhom": nhom_ma(e["status"]),
            "size": e["size"],
            "agent": e["agent"],
            "loai": loai_list if loai_list else ["Binh thuong"],
            "nguy": nguy,
            "ly_do": "; ".join(f"{n[0]} -> {n[2]}" for n in nhan),
        })
    return rows


HTML = r"""
<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>He thong giam sat tan cong web</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  * { box-sizing: border-box; }
  body { font-family: Arial, sans-serif; margin:0; background:#f1f5f9; color:#1f2937; }
  header { background:#111827; color:#fff; padding:14px 24px; }
  header h1 { margin:0; font-size:19px; }
  .tabs { display:flex; gap:8px; padding:12px 24px 0; background:#111827; }
  .tab { padding:9px 18px; border-radius:8px 8px 0 0; cursor:pointer; color:#cbd5e1;
         background:#1f2937; font-size:14px; }
  .tab.active { background:#f1f5f9; color:#111827; font-weight:bold; }
  .wrap { padding:22px 24px; max-width:1200px; margin:auto; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:18px; }
  .card { background:#fff; border-radius:10px; padding:14px 18px; flex:1; min-width:120px;
          box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .card .num { font-size:24px; font-weight:bold; }
  .card .lbl { color:#6b7280; font-size:12px; margin-top:2px; }
  .c2 { color:#16a34a; } .c3 { color:#0891b2; } .c4 { color:#d97706; }
  .c5 { color:#dc2626; } .cr { color:#dc2626; }
  .box { background:#fff; border-radius:10px; padding:18px; margin-bottom:18px;
         box-shadow:0 1px 3px rgba(0,0,0,.08); }
  h2 { font-size:15px; margin:0 0 12px; }
  .filters { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  select, input { padding:8px 10px; border:1px solid #d1d5db; border-radius:7px; font-size:13px; }
  input { min-width:180px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:7px 9px; border-bottom:1px solid #eee; }
  th { background:#f9fafb; position:sticky; top:0; }
  tbody tr { cursor:pointer; }
  tbody tr:hover { background:#f8fafc; }
  .st { font-weight:bold; padding:1px 7px; border-radius:6px; color:#fff; font-size:12px; }
  .s2 { background:#16a34a; } .s3 { background:#0891b2; }
  .s4 { background:#d97706; } .s5 { background:#dc2626; }
  .badge { padding:2px 8px; border-radius:12px; font-size:11px; color:#fff; margin-right:3px;
           display:inline-block; }
  .bCAO { background:#dc2626; } .bTB { background:#f59e0b; } .bOK { background:#9ca3af; }
  .tbl-scroll { max-height:520px; overflow:auto; }
  .muted { color:#9ca3af; font-size:12px; }
  /* Modal chi tiet */
  .overlay { position:fixed; inset:0; background:rgba(0,0,0,.5); display:none;
             align-items:center; justify-content:center; padding:20px; z-index:50; }
  .modal { background:#fff; border-radius:12px; padding:22px; max-width:640px; width:100%;
           max-height:85vh; overflow:auto; }
  .modal h3 { margin:0 0 14px; }
  .kv { display:grid; grid-template-columns:140px 1fr; gap:6px 12px; font-size:13px; }
  .kv b { color:#6b7280; font-weight:normal; }
  .kv span { word-break:break-all; }
  .close { float:right; cursor:pointer; color:#9ca3af; font-size:20px; line-height:1; }
  .doc table td { vertical-align:top; }
  .doc code { background:#f3f4f6; padding:1px 5px; border-radius:4px; }
  .page { display:none; } .page.active { display:block; }
</style>
</head>
<body>
<header><h1>He thong giam sat &amp; phat hien tan cong ung dung web</h1></header>
<div class="tabs">
  <div class="tab active" onclick="moTab('giamsat')">Giam sat</div>
  <div class="tab" onclick="moTab('tailieu')">Tai lieu ky thuat</div>
</div>

<!-- ================= TAB GIAM SAT ================= -->
<div class="wrap page active" id="giamsat">

  <div class="cards">
    <div class="card"><div class="num">{{ tong }}</div><div class="lbl">Tong request</div></div>
    <div class="card"><div class="num c2">{{ by['2xx'] }}</div><div class="lbl">2xx Thanh cong</div></div>
    <div class="card"><div class="num c3">{{ by['3xx'] }}</div><div class="lbl">3xx Chuyen huong</div></div>
    <div class="card"><div class="num c4">{{ by['4xx'] }}</div><div class="lbl">4xx Loi client</div></div>
    <div class="card"><div class="num c5">{{ by['5xx'] }}</div><div class="lbl">5xx Loi server</div></div>
    <div class="card"><div class="num">{{ so_ip }}</div><div class="lbl">So IP khac nhau</div></div>
    <div class="card"><div class="num cr">{{ so_canh_bao }}</div><div class="lbl">Request nghi tan cong</div></div>
  </div>

  <div class="box">
    <h2>Luu luong request theo phut</h2>
    <canvas id="bd" height="80"></canvas>
  </div>

  <div class="box">
    <h2>Nhat ky request</h2>
    <div class="filters">
      <label>Ma trang thai:
        <select id="fStatus" onchange="loc()">
          <option value="all">Tat ca</option>
          <option value="2xx">2xx - Thanh cong</option>
          <option value="3xx">3xx - Chuyen huong</option>
          <option value="4xx">4xx - Loi client</option>
          <option value="5xx">5xx - Loi server</option>
        </select>
      </label>
      <label>Phan loai:
        <select id="fLoai" onchange="loc()">
          <option value="all">Tat ca</option>
          <option value="Binh thuong">Binh thuong</option>
          <option value="SQL Injection">SQL Injection</option>
          <option value="XSS">XSS</option>
          <option value="Cong cu quet">Cong cu quet</option>
          <option value="Do tim duong dan nhay cam">Do tim duong dan</option>
          <option value="DoS">DoS</option>
          <option value="DDoS">DDoS</option>
        </select>
      </label>
      <input id="fTim" oninput="loc()" placeholder="Tim theo IP hoac URL...">
      <span class="muted" id="demKq"></span>
    </div>
    <div class="tbl-scroll" style="margin-top:12px;">
      <table>
        <thead><tr>
          <th>Thoi gian</th><th>IP</th><th>Method</th><th>URL</th>
          <th>Ma</th><th>Phan loai</th>
        </tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ================= TAB TAI LIEU ================= -->
<div class="wrap page doc" id="tailieu">
  <div class="box">
    <h2>1. Y nghia cac ma trang thai HTTP</h2>
    <table>
      <tr><th>Ma</th><th>Ten</th><th>Y nghia</th><th>Lien quan bao mat</th></tr>
      <tr><td><code>200</code></td><td>OK</td><td>Request thanh cong</td><td>Binh thuong</td></tr>
      <tr><td><code>301/302</code></td><td>Redirect</td><td>Chuyen huong trang</td><td>Binh thuong</td></tr>
      <tr><td><code>304</code></td><td>Not Modified</td><td>Dung lai cache</td><td>Binh thuong</td></tr>
      <tr><td><code>400</code></td><td>Bad Request</td><td>Request sai cu phap</td><td>Co the do payload tan cong bi loi</td></tr>
      <tr><td><code>401</code></td><td>Unauthorized</td><td>Chua dang nhap</td><td>Nhieu 401 lien tuc = do mat khau (brute-force)</td></tr>
      <tr><td><code>403</code></td><td>Forbidden</td><td>Khong du quyen</td><td>Co the dang do quyen truy cap</td></tr>
      <tr><td><code>404</code></td><td>Not Found</td><td>Khong tim thay trang</td><td>Nhieu 404 tu 1 IP = dang quet / do duong dan</td></tr>
      <tr><td><code>429</code></td><td>Too Many Requests</td><td>Gui qua nhieu</td><td>Dau hieu DoS / spam</td></tr>
      <tr><td><code>500</code></td><td>Server Error</td><td>Loi phia server</td><td>SQL Injection hay gay loi 500</td></tr>
      <tr><td><code>503</code></td><td>Unavailable</td><td>Server qua tai</td><td>Dau hieu DDoS lam sap server</td></tr>
    </table>
  </div>
  <div class="box">
    <h2>2. Cach phan biet cac loai tan cong</h2>
    <table>
      <tr><th>Loai</th><th>Dua vao dau de nhan biet</th><th>Vi du dau hieu</th></tr>
      <tr><td><b>DoS</b></td><td>1 IP gui qua nhieu request trong 1 phut (nguong {{ dos }})</td>
          <td>IP X gui 150 request/phut</td></tr>
      <tr><td><b>DDoS</b></td><td>Tong request tang vot + rat nhieu IP khac nhau cung luc
          (&gt;{{ ddos_tong }} request &amp; &gt;{{ ddos_ip }} IP/phut)</td>
          <td>400 request tu 300 IP trong 1 phut</td></tr>
      <tr><td><b>SQL Injection</b></td><td>URL/tham so chua cu phap SQL</td>
          <td><code>' OR 1=1</code>, <code>UNION SELECT</code>, <code>SLEEP()</code>, <code>--</code></td></tr>
      <tr><td><b>XSS</b></td><td>URL/tham so chua ma HTML/JS</td>
          <td><code>&lt;script&gt;</code>, <code>onerror=</code>, <code>document.cookie</code></td></tr>
      <tr><td><b>Cong cu quet</b></td><td>User-Agent la ten cong cu tan cong</td>
          <td><code>sqlmap</code>, <code>nikto</code>, <code>nmap</code></td></tr>
      <tr><td><b>Do tim duong dan</b></td><td>Truy cap cac duong dan quan tri / file nhay cam</td>
          <td><code>/wp-admin</code>, <code>/.env</code>, <code>/phpmyadmin</code></td></tr>
    </table>
    <p class="muted">Cach phan biet nhanh: tan cong <b>theo noi dung</b> (SQLi, XSS) nhin vao URL;
    tan cong <b>theo so luong</b> (DoS, DDoS) nhin vao so request/phut;
    tan cong <b>do tham do</b> (quet, do duong dan) nhin vao User-Agent va ma 404.</p>
  </div>
</div>

<!-- Modal chi tiet 1 request -->
<div class="overlay" id="overlay" onclick="if(event.target.id==='overlay')dong()">
  <div class="modal">
    <span class="close" onclick="dong()">&times;</span>
    <h3>Chi tiet request</h3>
    <div class="kv" id="ctiet"></div>
  </div>
</div>

<script>
const DATA = {{ rows|tojson }};
const NHAN_MA = {
  200:"OK - thanh cong", 201:"Created", 204:"No Content",
  301:"Moved Permanently", 302:"Found - chuyen huong", 304:"Not Modified",
  400:"Bad Request", 401:"Unauthorized - chua dang nhap", 403:"Forbidden - bi cam",
  404:"Not Found - khong tim thay", 405:"Method Not Allowed",
  429:"Too Many Requests - qua nhieu (nghi DoS)",
  500:"Internal Server Error - loi server (co the do SQLi)",
  502:"Bad Gateway", 503:"Service Unavailable - qua tai (nghi DDoS)"
};

function badge(r){
  const cls = r.nguy === 'CAO' ? 'bCAO' : (r.nguy === 'TB' ? 'bTB' : 'bOK');
  return r.loai.map(x => '<span class="badge '+cls+'">'+x+'</span>').join('');
}

function ve(rows){
  const tb = document.getElementById('tbody');
  tb.innerHTML = rows.map(r =>
    '<tr onclick="xem('+r._i+')">'
    + '<td>'+r.tg+'</td>'
    + '<td>'+r.ip+'</td>'
    + '<td>'+r.method+'</td>'
    + '<td style="max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+r.url+'</td>'
    + '<td><span class="st s'+r.nhom[0]+'">'+r.status+'</span></td>'
    + '<td>'+badge(r)+'</td>'
    + '</tr>'
  ).join('');
  document.getElementById('demKq').textContent = 'Hien ' + rows.length + '/' + DATA.length + ' request';
}

function loc(){
  const s = document.getElementById('fStatus').value;
  const l = document.getElementById('fLoai').value;
  const t = document.getElementById('fTim').value.toLowerCase();
  const kq = DATA.filter(r =>
    (s === 'all' || r.nhom === s) &&
    (l === 'all' || r.loai.includes(l)) &&
    (t === '' || r.ip.toLowerCase().includes(t) || r.url.toLowerCase().includes(t))
  );
  ve(kq);
}

function xem(i){
  const r = DATA[i];
  const ten = NHAN_MA[r.status] || ('Ma ' + r.status);
  document.getElementById('ctiet').innerHTML =
    '<b>Thoi gian</b><span>'+r.tg+'</span>'
    + '<b>Dia chi IP</b><span>'+r.ip+'</span>'
    + '<b>Method</b><span>'+r.method+'</span>'
    + '<b>URL (goc)</b><span>'+r.url+'</span>'
    + '<b>URL (giai ma)</b><span>'+r.url_giai_ma+'</span>'
    + '<b>Ma trang thai</b><span>'+r.status+' - '+ten+'</span>'
    + '<b>Kich thuoc</b><span>'+r.size+' byte</span>'
    + '<b>User-Agent</b><span>'+r.agent+'</span>'
    + '<b>Phan loai</b><span>'+r.loai.join(', ')+' (muc do: '+r.nguy+')</span>'
    + '<b>Ly do danh dau</b><span>'+(r.ly_do || 'Khong co dau hieu tan cong')+'</span>';
  document.getElementById('overlay').style.display = 'flex';
}
function dong(){ document.getElementById('overlay').style.display = 'none'; }

function moTab(id){
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  event.target.classList.add('active');
}

// Gan chi so cho tung dong roi ve bang lan dau
DATA.forEach((r,i) => r._i = i);
ve(DATA);

// Bieu do request/phut
new Chart(document.getElementById('bd'), {
  type: 'line',
  data: {
    labels: {{ nhan_bd|tojson }},
    datasets: [{ label:'Request/phut', data: {{ so_bd|tojson }},
      borderColor:'#2563eb', backgroundColor:'rgba(37,99,235,.1)', fill:true, tension:.3 }]
  },
  options: { plugins:{ legend:{ display:false } } }
});
</script>
</body>
</html>
"""


@app.route("/")
def trang_chu():
    try:
        entries = parser.parse_file(LOG_FILE)
    except FileNotFoundError:
        return "Chua co file access.log. Hay chay: python3 make_sample_log.py"

    rows = xay_du_lieu(entries)

    # Thong ke
    by = Counter(r["nhom"] for r in rows)
    for k in ("2xx", "3xx", "4xx", "5xx"):
        by.setdefault(k, 0)
    so_ip = len(set(r["ip"] for r in rows))
    so_canh_bao = sum(1 for r in rows if r["nguy"] != "OK")

    # Du lieu bieu do theo phut
    theo_phut = defaultdict(int)
    for e in entries:
        if e["dt"]:
            theo_phut[e["dt"].strftime("%H:%M")] += 1
    nhan_bd = sorted(theo_phut.keys())
    so_bd = [theo_phut[k] for k in nhan_bd]

    return render_template_string(
        HTML,
        rows=rows, by=by, tong=len(rows), so_ip=so_ip, so_canh_bao=so_canh_bao,
        nhan_bd=nhan_bd, so_bd=so_bd,
        dos=detect.DOS_NGUONG, ddos_tong=detect.DDOS_TONG, ddos_ip=detect.DDOS_SO_IP,
    )


if __name__ == "__main__":
    print("Mo trinh duyet: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
