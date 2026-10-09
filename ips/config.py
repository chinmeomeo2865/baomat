# -*- coding: utf-8 -*-
"""
config.py
Toàn bộ ngưỡng phát hiện và chế tài của IPS nằm ở đây, chỉnh một chỗ là đủ.
Các ngưỡng DoS/DDoS đặt thấp để demo bằng tay được.
"""

# ------- Cửa sổ trượt dùng cho luật tần suất (DoS, DDoS) -------
CUA_SO = 10              # xét các request trong 10 giây gần nhất

DOS_NGUONG = 15          # 1 IP gửi > 15 request / CUA_SO        => DoS
DDOS_TONG = 40           # tổng > 40 request / CUA_SO ...
DDOS_SO_IP = 8           # ... VÀ từ > 8 IP khác nhau            => DDoS

# ------- Điểm vi phạm & khoá IP theo bậc -------
DIEM_DE_KHOA = 3         # đủ 3 điểm vi phạm ...
THOI_HAN_DIEM = 600      # ... trong 10 phút thì khoá IP
BAC_KHOA = [300, 900, 3600]   # lần khoá thứ 1 / 2 / 3 trở đi: 5 / 15 / 60 phút

# ------- Chế độ khẩn cấp DDoS -------
KHAN_CAP_TAT_SAU = 10    # tắt khi 10 giây liên tiếp không còn vượt ngưỡng DDoS
IP_QUEN_TRUOC = 10       # "IP quen" = có request sạch sớm hơn lúc bật khẩn cấp ít nhất 10 giây

RETRY_AFTER = CUA_SO     # header Retry-After (giây) gửi kèm mã 429

# ------- Lưu trữ -------
SO_REQUEST_LUU = 1000    # số request gần nhất giữ trong RAM cho dashboard
SO_CANH_BAO_LUU = 100    # số cảnh báo gần nhất
FILE_LOG = "realtime_access.log"   # mọi request ghi thêm ra file, định dạng log của Nginx

# Máy chạy server: chỉ tin X-Forwarded-For từ đây (để demo giả lập nhiều IP),
# và chỉ cho phép thao tác quản trị (mở khoá IP, xoá dữ liệu) từ đây.
MAY_TIN_CAY = ("127.0.0.1", "::1")

# ------- Các kiểu chế tài một luật có thể khai báo (biến CHE_TAI trong mỗi file luật) -------
CONG_DIEM = "cong_diem"  # cộng 1 điểm vi phạm, đủ điểm thì khoá IP
KHOA_NGAY = "khoa_ngay"  # khoá IP ngay lập tức
KHAN_CAP = "khan_cap"    # bật chế độ khẩn cấp toàn hệ thống (DDoS)
