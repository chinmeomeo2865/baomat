# -*- coding: utf-8 -*-
"""
attack_demo.py
Kịch bản tấn công tự động để demo IPS: cho thấy từng loại tấn công bị chặn ra sao
và chế tài theo bậc hoạt động thế nào. Dùng header X-Forwarded-For để giả lập nhiều IP.

Server phải đang chạy trước:  python server.py
Rồi chạy:                     python attack_demo.py
Xem trực tiếp tại:            http://127.0.0.1:5000/__monitor
"""

import json
import random
import sys
import threading
import time
from collections import Counter
from urllib import request as ureq
from urllib.parse import quote

SERVER = "http://127.0.0.1:5000"
IP_QUEN = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]   # người dùng thật, truy cập từ đầu


def ban(path, ip, agent="Mozilla/5.0 (demo)", method="GET", body=None):
    """Gửi 1 request, trả về (mã HTTP, nội dung JSON)."""
    url = SERVER + quote(path, safe="/?=&")
    headers = {"User-Agent": agent, "X-Forwarded-For": ip}
    req = ureq.Request(url, data=body.encode() if body else None, headers=headers, method=method)
    try:
        with ureq.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except ureq.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def in_kq(path, ip, **kw):
    code, j = ban(path, ip, **kw)
    che_tai = j.get("che_tai", "")
    print(f"  [{code}] {ip:<15} {path:<45} {che_tai}")
    return code


def ip_ngau_nhien():
    return f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def cho_cua_so(ly_do):
    """Chờ cửa sổ trượt 10 giây trôi qua để bước sau không bị lẫn lưu lượng của bước trước."""
    print(f"  ... chờ 11 giây ({ly_do})")
    time.sleep(11)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    try:
        ureq.urlopen(ureq.Request(SERVER + "/__reset", method="POST", headers={"X-IPS-Admin": "1"}), timeout=5)
        print(">> Đã xoá dữ liệu cũ trên IPS\n")
    except Exception as e:
        print(f"Không kết nối được server ({e}). Hãy chạy python server.py trước.")
        return

    print(">> 1. Người dùng thật (IP quen) truy cập bình thường")
    for ip in IP_QUEN:
        for p in ["/", "/products", "/cart"]:
            in_kq(p, ip)

    print("\n>> 2. SQL Injection và XSS từ các IP khác nhau: mỗi IP bị chặn 403, +1 điểm")
    for p in ["/product?id=1' OR '1'='1", "/search?q=1 UNION SELECT user,pass FROM users",
              "/item?id=1 AND 1=1", "/comment?text=<script>alert(1)</script>",
              "/search?q=<img src=x onerror=alert(document.cookie)>"]:
        in_kq(p, ip_ngau_nhien())

    print("\n>> 3. Một IP thử SQLi liên tục: lần 3 bị khoá, lần 4 nhận 'IP bị khoá'")
    for p in ["/login?user=admin'--", "/login?user=admin'#", "/login?user=' OR 'a'='a", "/products"]:
        in_kq(p, "203.0.113.50")

    print("\n>> 4. Dò đường dẫn nhạy cảm: /administrator-guide không bị chặn nhầm, các file bí mật bị chặn")
    for p in ["/administrator-guide", "/.env", "/.git/config", "/wp-admin", "/backup.zip"]:
        in_kq(p, "185.9.9.9")

    print("\n>> 5. Công cụ quét (sqlmap): khoá IP ngay từ request đầu tiên")
    in_kq("/", "103.20.5.7", agent="sqlmap/1.7")
    in_kq("/products", "103.20.5.7")

    cho_cua_so("để đợt DoS không bị lẫn với các bước trên")
    print("\n>> 6. DoS: 1 IP bắn 25 request liên tục")
    kq = [ban("/", "45.77.10.99", agent="python-requests/2.31")[0] for _ in range(25)]
    print(f"  Kết quả theo thứ tự: {' '.join(map(str, kq))}")
    print("  -> 15 request đầu 200, vượt ngưỡng thì 429 (+1 điểm), đủ 3 điểm thì bị khoá (403)")

    cho_cua_so("để các IP quen đủ 'cũ' trước khi DDoS bắt đầu")
    print("\n>> 7. DDoS: 80 request từ 80 IP lạ cùng lúc, trong lúc đó IP quen vẫn truy cập")
    ket_qua_bot, ket_qua_quen = Counter(), []

    def bot():
        ket_qua_bot[ban("/", ip_ngau_nhien(), agent="Go-http-client/1.1")[0]] += 1

    luong = [threading.Thread(target=bot) for _ in range(80)]
    for t in luong:
        t.start()
    time.sleep(0.5)
    for ip in IP_QUEN:
        ket_qua_quen.append((ip, ban("/products", ip)[0]))
    for t in luong:
        t.join()
    print(f"  Bot: {dict(ket_qua_bot)}  (đầu đợt còn lọt 200, khi khẩn cấp bật thì 429)")
    for ip, code in ket_qua_quen:
        print(f"  IP quen {ip}: {code}")
    print("  -> Chế độ khẩn cấp: IP lạ bị 429, người dùng thật vẫn vào được")

    print(f"\n[HOÀN TẤT] Xem kết quả tại {SERVER}/__monitor")


if __name__ == "__main__":
    main()
