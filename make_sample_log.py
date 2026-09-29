# -*- coding: utf-8 -*-
"""
make_sample_log.py
Tao 1 file access.log GIA LAP de demo he thong (khong tan cong web that).
Log gom:
  - Traffic binh thuong (nhieu IP, nhieu trang)
  - 1 dot DoS (1 IP ban lien tuc)
  - 1 dot DDoS (rat nhieu IP cung ban)
  - Vai request SQL Injection / XSS
  - Vai request tu cong cu quet (sqlmap, nikto)
  - Vai request do tim duong dan nhay cam

Cach dung:
    python3 make_sample_log.py
=> tao ra file access.log
"""

import random
from datetime import datetime, timedelta

FMT = '{ip} - - [{time}] "{method} {url} HTTP/1.1" {status} {size} "-" "{agent}"'

UA_THUONG = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/119.0",
]
TRANG_THUONG = ["/", "/index.html", "/products", "/about", "/login", "/cart", "/api/items"]


def ip_ngau_nhien():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def dong(ip, method, url, status, agent, t):
    return FMT.format(
        ip=ip, method=method, url=url, status=status,
        size=random.randint(200, 5000),
        agent=agent, time=t.strftime("%d/%b/%Y:%H:%M:%S +0700"),
    )


def main():
    logs = []
    t = datetime.now().replace(second=0, microsecond=0) - timedelta(minutes=10)

    # 1) Traffic binh thuong: 200 request rai deu
    for _ in range(200):
        logs.append(dong(
            ip_ngau_nhien(), "GET", random.choice(TRANG_THUONG),
            200, random.choice(UA_THUONG),
            t + timedelta(seconds=random.randint(0, 540)),
        ))

    # 2) DoS: 1 IP ban 150 request trong cung 1 phut
    ke_tan_cong = "45.77.10.99"
    t_dos = t + timedelta(minutes=3)
    for _ in range(150):
        logs.append(dong(
            ke_tan_cong, "GET", "/", 200, "python-requests/2.31",
            t_dos + timedelta(seconds=random.randint(0, 59)),
        ))

    # 3) DDoS: 80 IP khac nhau, tong ~400 request trong 1 phut
    t_ddos = t + timedelta(minutes=6)
    for _ in range(400):
        logs.append(dong(
            ip_ngau_nhien(), "GET", "/", 200, "Go-http-client/1.1",
            t_ddos + timedelta(seconds=random.randint(0, 59)),
        ))

    # 4) SQL Injection
    sqli = [
        "/product?id=1' OR '1'='1",
        "/search?q=1 UNION SELECT username,password FROM users",
        "/item?id=1; SELECT * FROM information_schema.tables",
        "/login?user=admin'--",
        "/api?id=1 AND SLEEP(5)",
    ]
    for u in sqli:
        logs.append(dong(ip_ngau_nhien(), "GET", u.replace(" ", "%20"),
                         500, random.choice(UA_THUONG),
                         t + timedelta(minutes=4, seconds=random.randint(0, 59))))

    # 5) XSS
    xss = [
        "/comment?text=<script>alert(1)</script>",
        "/search?q=<img src=x onerror=alert(document.cookie)>",
    ]
    for u in xss:
        logs.append(dong(ip_ngau_nhien(), "GET", u.replace(" ", "%20"),
                         200, random.choice(UA_THUONG),
                         t + timedelta(minutes=4, seconds=random.randint(0, 59))))

    # 6) Cong cu quet
    logs.append(dong("103.20.5.7", "GET", "/", 404, "sqlmap/1.7",
                     t + timedelta(minutes=5)))
    logs.append(dong("103.20.5.8", "GET", "/admin", 404, "Nikto/2.5",
                     t + timedelta(minutes=5, seconds=10)))

    # 7) Do tim duong dan nhay cam
    for u in ["/wp-admin", "/.env", "/phpmyadmin", "/.git/config"]:
        logs.append(dong("185.9.9.9", "GET", u, 404, random.choice(UA_THUONG),
                         t + timedelta(minutes=5, seconds=random.randint(0, 59))))

    # Sap xep theo thoi gian roi ghi ra file
    random.shuffle(logs)
    with open("access.log", "w", encoding="utf-8") as f:
        f.write("\n".join(logs) + "\n")

    print(f"Da tao access.log voi {len(logs)} dong (co ca traffic thuong va tan cong).")


if __name__ == "__main__":
    main()
