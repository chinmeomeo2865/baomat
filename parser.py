# -*- coding: utf-8 -*-
"""
parser.py
Đọc file access.log của web server (Nginx/Apache - định dạng "combined")
và trả về từng dòng dưới dạng dictionary để dễ xử lý.

Định dạng combined (mặc định của Nginx):
127.0.0.1 - - [10/Oct/2025:13:55:36 +0700] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0 ..."
  IP        user   thời_gian        method  url       mã  size referer  user-agent
"""

import re
from datetime import datetime

# Biểu thức chính quy (regex) để tách 1 dòng log ra từng phần
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '            # địa chỉ IP
    r'\[(?P<time>[^\]]+)\] '           # thời gian
    r'"(?P<method>\S+) (?P<url>.*?) \S+" '  # method + url
    r'(?P<status>\d{3}) '              # mã trạng thái (200, 404, 500...)
    r'(?P<size>\S+) '                  # kích thước phản hồi
    r'"(?P<referer>.*?)" '             # trang giới thiệu
    r'"(?P<agent>.*?)"'                # trình duyệt / công cụ (User-Agent)
)


def parse_line(line):
    """Đọc 1 dòng log -> dictionary. Nếu dòng hỏng thì trả về None."""
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None

    d = m.groupdict()

    # Chuyển thời gian về dạng datetime của Python
    try:
        d["dt"] = datetime.strptime(d["time"].split()[0], "%d/%b/%Y:%H:%M:%S")
    except Exception:
        d["dt"] = None

    d["status"] = int(d["status"])
    return d


def parse_file(path):
    """Đọc cả file log -> danh sách các dictionary."""
    entries = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            e = parse_line(line)
            if e:
                entries.append(e)
    return entries


# Chạy thử: python3 parser.py access.log
if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "access.log"
    data = parse_file(path)
    print(f"Đọc được {len(data)} dòng hợp lệ từ {path}")
    for e in data[:3]:
        print(e["ip"], e["method"], e["url"], e["status"])
