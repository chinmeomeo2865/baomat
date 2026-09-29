# -*- coding: utf-8 -*-
"""
dashboard.py
Trang web hien thi ket qua giam sat: bieu do request/phut, top IP,
va bang canh bao tan cong. Moi lan mo trang la doc lai file log.

Cach dung:
    python3 dashboard.py
    -> mo trinh duyet: http://127.0.0.1:5000
"""

from collections import Counter, defaultdict
from flask import Flask, render_template_string

import parser
import detect

LOG_FILE = "access.log"
app = Flask(__name__)

HTML = """
<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <title>He thong giam sat tan cong web</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; background:#f4f6f9; color:#222; }
    header { background:#1f2937; color:#fff; padding:16px 24px; }
    header h1 { margin:0; font-size:20px; }
    .wrap { padding:24px; max-width:1100px; margin:auto; }
    .cards { display:flex; gap:16px; flex-wrap:wrap; margin-bottom:20px; }
    .card { background:#fff; border-radius:10px; padding:16px 20px; flex:1; min-width:160px;
            box-shadow:0 1px 3px rgba(0,0,0,.1); }
    .card .num { font-size:28px; font-weight:bold; }
    .card .lbl { color:#666; font-size:13px; }
    .red { color:#dc2626; }
    .box { background:#fff; border-radius:10px; padding:20px; margin-bottom:20px;
           box-shadow:0 1px 3px rgba(0,0,0,.1); }
    h2 { font-size:16px; margin-top:0; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #eee; }
    th { background:#f9fafb; }
    .badge { padding:2px 8px; border-radius:12px; font-size:12px; color:#fff; }
    .CAO { background:#dc2626; }
    .TRUNG.BINH, .tb { background:#f59e0b; }
    .refresh { float:right; font-size:13px; color:#9ca3af; }
  </style>
</head>
<body>
  <header><h1>He thong giam sat &amp; phat hien tan cong ung dung web</h1></header>
  <div class="wrap">

    <div class="cards">
      <div class="card"><div class="num">{{ tong }}</div><div class="lbl">Tong request</div></div>
      <div class="card"><div class="num">{{ so_ip }}</div><div class="lbl">So IP khac nhau</div></div>
      <div class="card"><div class="num">{{ loi }}</div><div class="lbl">Request loi (4xx/5xx)</div></div>
      <div class="card"><div class="num red">{{ so_canh_bao }}</div><div class="lbl">Canh bao tan cong</div></div>
    </div>

    <div class="box">
      <h2>Luu luong request theo phut</h2>
      <canvas id="bd" height="90"></canvas>
    </div>

    <div class="box">
      <h2>Top 10 IP gui nhieu nhat</h2>
      <table>
        <tr><th>IP</th><th>So request</th></tr>
        {% for ip, so in top_ip %}
        <tr><td>{{ ip }}</td><td>{{ so }}</td></tr>
        {% endfor %}
      </table>
    </div>

    <div class="box">
      <h2>Danh sach canh bao <span class="refresh">Tai lai trang de cap nhat</span></h2>
      <table>
        <tr><th>Thoi gian</th><th>IP</th><th>Loai tan cong</th><th>Muc do</th><th>Chi tiet</th></tr>
        {% for c in canh_bao %}
        <tr>
          <td>{{ c.thoi_gian }}</td>
          <td>{{ c.ip }}</td>
          <td>{{ c.loai }}</td>
          <td><span class="badge {{ 'CAO' if c.muc_do=='CAO' else 'tb' }}">{{ c.muc_do }}</span></td>
          <td>{{ c.chi_tiet }}</td>
        </tr>
        {% endfor %}
      </table>
    </div>

  </div>
  <script>
    new Chart(document.getElementById('bd'), {
      type: 'line',
      data: {
        labels: {{ nhan|tojson }},
        datasets: [{
          label: 'Request/phut', data: {{ so_luong|tojson }},
          borderColor:'#2563eb', backgroundColor:'rgba(37,99,235,.1)', fill:true, tension:.3
        }]
      },
      options: { plugins:{legend:{display:false}} }
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

    # Thong ke chung
    tong = len(entries)
    ip_dem = Counter(e["ip"] for e in entries)
    so_ip = len(ip_dem)
    loi = sum(1 for e in entries if e["status"] >= 400)

    # Request theo phut (cho bieu do)
    theo_phut = defaultdict(int)
    for e in entries:
        if e["dt"]:
            theo_phut[e["dt"].strftime("%H:%M")] += 1
    nhan = sorted(theo_phut.keys())
    so_luong = [theo_phut[k] for k in nhan]

    # Canh bao
    canh_bao = detect.phan_tich(entries)

    return render_template_string(
        HTML,
        tong=tong, so_ip=so_ip, loi=loi,
        so_canh_bao=len(canh_bao),
        top_ip=ip_dem.most_common(10),
        nhan=nhan, so_luong=so_luong,
        canh_bao=canh_bao,
    )


if __name__ == "__main__":
    print("Mo trinh duyet: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
