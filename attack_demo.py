# -*- coding: utf-8 -*-
"""
attack_demo.py
Bắn thử request tới server (giống Postman nhưng tự động) để demo.
Gồm: request bình thường + SQLi + XSS + công cụ quét + dò đường dẫn,
rồi 1 đợt DoS (1 IP) và 1 đợt DDoS (nhiều IP).

Server phải đang chạy trước:  python3 server.py
Rồi chạy:  python3 attack_demo.py
Xem kết quả hiện trực tiếp ở: http://127.0.0.1:5000/__monitor
"""

import time
import random
import threading
from urllib import request as ureq
from urllib.parse import quote

SERVER = "http://127.0.0.1:5000"


def ban(path, ip=None, agent="Mozilla/5.0 (demo)", method="GET", body=None, im_lang=False):
    """Gửi 1 request. Dùng header X-Forwarded-For để giả lập IP khác nhau."""
    url = SERVER + quote(path, safe="/?=&")   # mã hóa an toàn ký tự đặc biệt
    headers = {"User-Agent": agent}
    if ip:
        headers["X-Forwarded-For"] = ip
    data = body.encode() if body else None
    req = ureq.Request(url, data=data, headers=headers, method=method)
    try:
        ureq.urlopen(req, timeout=3).read()
        if not im_lang:
            print(f"  [200 OK - HỢP LỆ]: {path}")
    except Exception as ex:
        if hasattr(ex, "code"):
            if not im_lang:
                print(f"  [{ex.code} BỊ IPS CHẶN]: {path}")
        else:
            if not im_lang:
                print(f"  (lỗi gửi: {ex})")


def ip_ngau_nhien():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def main():
    print(">> 1. Vài request BÌNH THƯỜNG...")
    for p in ["/", "/products", "/about", "/login", "/cart"]:
        ban(p, ip=ip_ngau_nhien())
        time.sleep(0.2)

    print("\n>> 2. SQL Injection (Kỳ vọng: Bị IPS chặn 403)...")
    for p in ["/product?id=1' OR '1'='1",
              "/search?q=1 UNION SELECT user,pass FROM users",
              "/login?user=admin'--"]:
        ban(p, ip=ip_ngau_nhien())
        time.sleep(0.2)

    print("\n>> 3. XSS (Kỳ vọng: Bị IPS chặn 403)...")
    ban("/comment?text=<script>alert(1)</script>", ip=ip_ngau_nhien())
    ban("/search?q=<img src=x onerror=alert(document.cookie)>", ip=ip_ngau_nhien())
    time.sleep(0.2)

    print("\n>> 4. Công cụ quét (Kỳ vọng: Bị IPS chặn 403)...")
    ban("/", ip="103.20.5.7", agent="sqlmap/1.7")
    ban("/admin", ip="103.20.5.8", agent="Nikto/2.5")
    time.sleep(0.2)

    print("\n>> 5. Dò tìm đường dẫn nhạy cảm (Kỳ vọng: Bị IPS chặn 403)...")
    for p in ["/wp-admin", "/.env", "/phpmyadmin", "/.git/config"]:
        ban(p, ip="185.9.9.9")
        time.sleep(0.1)

    print("\n>> 6. Tấn công DoS: 1 IP bắn 25 request thật nhanh...")
    for _ in range(25):
        ban("/", ip="45.77.10.99", agent="python-requests/2.31", im_lang=True)
    print("  -> Đã gửi 25 request DoS (IPS sẽ chuyển sang chặn 429 khi vượt ngưỡng)")

    print("\n>> 7. Tấn công DDoS: 60 request từ nhiều IP khác nhau (đa luồng)...")
    def mot_phat():
        ban("/", ip=ip_ngau_nhien(), agent="Go-http-client/1.1", im_lang=True)
    luong = [threading.Thread(target=mot_phat) for _ in range(60)]
    for t in luong:
        t.start()
    for t in luong:
        t.join()
    print("  -> Đã gửi 60 request DDoS từ nhiều IP phân tán")

    print("\n[HOÀN TẤT] Mở http://127.0.0.1:5000/__monitor để xem bảng nhật ký chặn của IPS.")


if __name__ == "__main__":
    main()
