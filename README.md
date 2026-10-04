# Hệ thống giám sát & phát hiện tấn công ứng dụng web

Đề tài môn **Bảo mật ứng dụng và hệ thống**.
Hệ thống đọc **file log** của web server (Nginx/Apache) rồi phát hiện dấu hiệu tấn công.
Vì chỉ đọc log nên **áp dụng được cho mọi web** (PHP, Node, Java...) mà không cần sửa code web.

## Các loại tấn công phát hiện được

| Loại tấn công (trong bài học) | Cách phát hiện |
|---|---|
| 1. DoS | 1 IP gửi quá nhiều request trong 1 phút (ngưỡng: 100) |
| 2. DDoS | Tổng request tăng vọt + rất nhiều IP khác nhau cùng lúc |
| 5. SQL Injection | Dò khớp mẫu: `OR 1=1`, `UNION SELECT`, `SLEEP()`, `--`... |
| (Thêm) XSS | Mẫu: `<script>`, `onerror=`, `document.cookie` |
| (Thêm) Công cụ quét | User-Agent: sqlmap, nikto, nmap... |
| (Thêm) Dò tìm đường dẫn | `/wp-admin`, `/.env`, `/phpmyadmin`... |

**Lưu ý trong báo cáo** (3 loại khó làm bằng log web, nên trình bày lý thuyết / mở rộng):
- **Giả mạo DNS**: xảy ra phía người dùng, server không thấy trong log. Phòng chống: DNSSEC, HTTPS, HSTS.
- **Session Hijacking**: cần đặt reverse proxy để đọc cookie, so sánh IP/User-Agent theo từng session.
- **Trojan/Virus/Worm**: là mã độc trên máy, không phải request HTTP. Phần liên quan web: quét file upload (ClamAV), phát hiện webshell.

## Cấu trúc thư mục

| File | Chức năng |
|---|---|
| `server.py` | **(Chính) Server giám sát REALTIME**: nhận request thật → phân loại ngay → dashboard tự cập nhật |
| `attack_demo.py` | Bắn request thử (tốt + xấu + DoS + DDoS) để demo trực tiếp |
| `detect.py` | Các luật phát hiện tấn công (chỉnh ngưỡng ở đây) |
| `parser.py` | Đọc file log → tách thành IP, thời gian, URL, mã trạng thái... |
| `monitor.py` | Chạy trên terminal: đọc file log rồi in cảnh báo |
| `dashboard.py` | Dashboard đọc file log có sẵn (phân tích log cũ) |
| `make_sample_log.py` | Tạo file log mẫu để demo kiểu đọc log |

> Có **2 cách dùng**: (1) **Realtime** với `server.py` — server nhận request trực tiếp, phân loại và hiện ngay (demo sinh động nhất). (2) **Đọc log** với `dashboard.py` — phân tích file log đã có sẵn.

## Tính năng của dashboard

- Hiển thị **mọi request** (cả thành công lẫn lỗi), phân loại ngay trên bảng.
- Thống kê theo nhóm mã: **2xx / 3xx / 4xx / 5xx**.
- **Bộ lọc** theo mã trạng thái, theo loại tấn công, và **tìm theo IP / URL** để truy vết.
- **Click vào 1 request** để xem chi tiết đầy đủ + lý do bị đánh dấu.
- Tab **Tài liệu kỹ thuật**: ý nghĩa các mã HTTP + cách phân biệt từng loại tấn công.

## Cách chạy — CÁCH 1: Realtime (khuyên dùng để demo)

```bash
# 1. Cài thư viện
pip3 install flask

# 2. Chạy server giám sát
python3 server.py

# 3. Mở dashboard: http://127.0.0.1:5000/__monitor

# 4. Bắn request để test (chọn 1 trong 2):
#    - Bằng script tự động:
python3 attack_demo.py
#    - Hoặc bằng Postman / trình duyệt, gửi tới http://127.0.0.1:5000/...
#      vd SQLi: http://127.0.0.1:5000/product?id=1' OR '1'='1
```

Server nhận request → phân loại ngay → dashboard tự cập nhật mỗi 1.5 giây
(dòng mới tô sáng vàng). Giả lập nhiều IP bằng header `X-Forwarded-For`.

## Cách chạy — CÁCH 2: Đọc file log có sẵn

```bash
python3 make_sample_log.py       # tạo log mẫu
python3 monitor.py access.log    # xem trên terminal
python3 dashboard.py             # hoặc xem web: http://127.0.0.1:5000
```

## Dùng với web thật (không bắt buộc, phần nâng cao)

Thay vì dùng log mẫu, trỏ `LOG_FILE` trong `dashboard.py` tới log thật:
- Nginx: `/var/log/nginx/access.log`
- Apache: `/var/log/apache2/access.log`

## Gợi ý cấu trúc báo cáo

1. **Giới thiệu**: vấn đề — web bị tấn công, nhu cầu giám sát.
2. **Cơ sở lý thuyết**: mô tả 6 loại tấn công, khái niệm WAF/SIEM/log.
3. **Phân tích & thiết kế**: sơ đồ hệ thống, giải thích vì sao đọc log áp dụng được mọi web.
4. **Cài đặt**: giải thích từng file và từng luật phát hiện.
5. **Thử nghiệm (demo)**: chạy `make_sample_log.py` + chụp màn hình terminal và dashboard.
6. **Đánh giá**: ưu điểm, hạn chế (có thể bị bypass bằng mã hóa, báo nhầm...), so sánh với ModSecurity.
7. **Kết luận & hướng phát triển**: thêm tự động chặn IP, cảnh báo Telegram, module DNS...

## Hướng nâng cao (nếu còn thời gian)

- Tự động chặn IP xấu (ghi vào iptables hoặc danh sách đen của Nginx).
- Gửi cảnh báo qua Telegram / Email.
- Đọc log trực tiếp theo thời gian thực (tail -f).
- So sánh kết quả với ModSecurity + OWASP CRS.
