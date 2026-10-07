# -*- coding: utf-8 -*-
"""
monitor.py
Chạy trên dòng lệnh (terminal): đọc file log -> phân tích -> in cảnh báo.
Dùng để chụp màn hình demo, hoặc chạy định kỳ.

Cách dùng:
    python3 monitor.py access.log
"""

import sys
from collections import Counter

import parser
import detect


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "access.log"

    entries = parser.parse_file(path)
    print("=" * 60)
    print(f" ĐỌC LOG: {path}")
    print(f" Tổng số request hợp lệ: {len(entries)}")
    print("=" * 60)

    # Thống kê nhanh
    ip_dem = Counter(e["ip"] for e in entries)
    print("\n[ TOP 5 IP GỬI NHIỀU NHẤT ]")
    for ip, so in ip_dem.most_common(5):
        print(f"   {ip:<18} {so} request")

    loi = sum(1 for e in entries if e["status"] >= 400)
    print(f"\n Request lỗi (4xx/5xx): {loi}")

    # Phân tích tấn công
    canh_bao = detect.phan_tich(entries)
    print("\n" + "=" * 60)
    print(f" PHÁT HIỆN {len(canh_bao)} CẢNH BÁO")
    print("=" * 60)

    if not canh_bao:
        print(" Không phát hiện dấu hiệu tấn công.")
        return

    # Đếm theo loại
    theo_loai = Counter(c["loai"] for c in canh_bao)
    print("\n[ THỐNG KÊ THEO LOẠI ]")
    for loai, so in theo_loai.most_common():
        print(f"   {loai:<32} {so}")

    print("\n[ CHI TIẾT (20 cảnh báo đầu) ]")
    for c in canh_bao[:20]:
        print(f"   [{c['muc_do']:<10}] {c['loai']:<28} "
              f"IP={c['ip']:<16} {c['chi_tiet']}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")   # tránh lỗi in tiếng Việt trên terminal Windows
    main()
