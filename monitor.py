# -*- coding: utf-8 -*-
"""
monitor.py
Chay tren dong lenh (terminal): doc file log -> phan tich -> in canh bao.
Dung de chup man hinh demo, hoac chay dinh ky.

Cach dung:
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
    print(f" DOC LOG: {path}")
    print(f" Tong so request hop le: {len(entries)}")
    print("=" * 60)

    # Thong ke nhanh
    ip_dem = Counter(e["ip"] for e in entries)
    print("\n[ TOP 5 IP GUI NHIEU NHAT ]")
    for ip, so in ip_dem.most_common(5):
        print(f"   {ip:<18} {so} request")

    loi = sum(1 for e in entries if e["status"] >= 400)
    print(f"\n Request loi (4xx/5xx): {loi}")

    # Phan tich tan cong
    canh_bao = detect.phan_tich(entries)
    print("\n" + "=" * 60)
    print(f" PHAT HIEN {len(canh_bao)} CANH BAO")
    print("=" * 60)

    if not canh_bao:
        print(" Khong phat hien dau hieu tan cong.")
        return

    # Dem theo loai
    theo_loai = Counter(c["loai"] for c in canh_bao)
    print("\n[ THONG KE THEO LOAI ]")
    for loai, so in theo_loai.most_common():
        print(f"   {loai:<32} {so}")

    print("\n[ CHI TIET (20 canh bao dau) ]")
    for c in canh_bao[:20]:
        print(f"   [{c['muc_do']:<10}] {c['loai']:<28} "
              f"IP={c['ip']:<16} {c['chi_tiet']}")


if __name__ == "__main__":
    main()
