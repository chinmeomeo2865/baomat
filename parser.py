# -*- coding: utf-8 -*-
"""
parser.py
Doc file access.log cua web server (Nginx/Apache - dinh dang "combined")
va tra ve tung dong duoi dang dictionary de de xu ly.

Dinh dang combined (mac dinh cua Nginx):
127.0.0.1 - - [10/Oct/2025:13:55:36 +0700] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0 ..."
  IP        user   thoi_gian        method  url       code size referer  user-agent
"""

import re
from datetime import datetime

# Bieu thuc chinh quy (regex) de tach 1 dong log ra tung phan
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '            # dia chi IP
    r'\[(?P<time>[^\]]+)\] '           # thoi gian
    r'"(?P<method>\S+) (?P<url>.*?) \S+" '  # method + url
    r'(?P<status>\d{3}) '              # ma trang thai (200, 404, 500...)
    r'(?P<size>\S+) '                  # kich thuoc phan hoi
    r'"(?P<referer>.*?)" '             # trang gioi thieu
    r'"(?P<agent>.*?)"'                # trinh duyet / cong cu (User-Agent)
)


def parse_line(line):
    """Doc 1 dong log -> dictionary. Neu dong hong thi tra ve None."""
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None

    d = m.groupdict()

    # Chuyen thoi gian ve dang datetime cua Python
    try:
        d["dt"] = datetime.strptime(d["time"].split()[0], "%d/%b/%Y:%H:%M:%S")
    except Exception:
        d["dt"] = None

    d["status"] = int(d["status"])
    return d


def parse_file(path):
    """Doc ca file log -> danh sach cac dictionary."""
    entries = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            e = parse_line(line)
            if e:
                entries.append(e)
    return entries


# Chay thu: python3 parser.py access.log
if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "access.log"
    data = parse_file(path)
    print(f"Doc duoc {len(data)} dong hop le tu {path}")
    for e in data[:3]:
        print(e["ip"], e["method"], e["url"], e["status"])
