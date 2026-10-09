# Hệ thống ngăn chặn tấn công ứng dụng web (IPS)

Đề tài môn **Bảo mật ứng dụng và hệ thống**.

Hệ thống là một **IPS (Intrusion Prevention System) tầng ứng dụng**, đứng *inline* trước ứng dụng web. Mọi request đi qua 6 luật phát hiện. Request vi phạm bị chặn ngay (**403** / **429**), IP vi phạm phải chịu **chế tài theo bậc** (cộng điểm, khoá IP, chế độ khẩn cấp DDoS). Request sạch được cho qua (**200**). Mọi diễn biến hiển thị trực tiếp trên một giao diện giám sát duy nhất.

---

## Cấu trúc project

```
baomat/
├── server.py                 # Flask: route bắt mọi request + API cho giao diện giám sát
├── ips/
│   ├── config.py             # MỌI ngưỡng và thời gian khoá, chỉnh ở một chỗ
│   ├── engine.py             # Pipeline: kiểm tra khoá → chạy 6 luật → quyết định → ghi nhận
│   ├── sanctions.py          # Chế tài: điểm vi phạm, khoá IP theo bậc, khẩn cấp DDoS
│   ├── storage.py            # Lịch sử request, cảnh báo, file realtime_access.log
│   └── rules/
│       ├── __init__.py       # Gom 6 luật: CAC_LUAT = [sqli, xss, scanner, sensitive_path, dos, ddos]
│       ├── base.py           # Chuẩn hoá đầu vào (giải mã nhiều lớp) + quét từng trường
│       ├── sqli.py           # Luật 1: SQL Injection
│       ├── xss.py            # Luật 2: XSS
│       ├── scanner.py        # Luật 3: Công cụ quét lỗ hổng
│       ├── sensitive_path.py # Luật 4: Dò đường dẫn nhạy cảm
│       ├── dos.py            # Luật 5: DoS
│       └── ddos.py           # Luật 6: DDoS
├── templates/monitor.html    # Giao diện giám sát duy nhất
├── static/                   # monitor.css, monitor.js, chart.umd.min.js (chạy không cần Internet)
├── tests/                    # test_rules.py (từng luật), test_server.py (toàn hệ thống)
└── attack_demo.py            # Kịch bản tấn công tự động để demo
```

Mọi file luật đều khai báo cùng một bộ thành phần, nên đọc file nào cũng thấy cấu trúc giống nhau:

```python
MA = "sqli"                    # khoá dùng trong code/JSON
TEN = "SQL Injection"          # tên hiển thị
MUC_DO = "CAO"                 # CAO | TB
PHAN_HOI = 403                 # mã HTTP khi luật này chặn
CHE_TAI = config.CONG_DIEM     # CONG_DIEM | KHOA_NGAY | KHAN_CAP
def kiem_tra(req, lich_su):    # -> chuỗi chi tiết nếu vi phạm, None nếu sạch
```

---

## Luồng xử lý một request (`ips/engine.py`)

1. **IP đang bị khoá?** Có thì trả 403 ngay, không phân tích thêm.
2. **Chuẩn hoá:** giải mã `%xx` nhiều lớp (chống `%2527`), bỏ comment SQL `/**/` (chống `UN/**/ION`).
3. **Chạy 6 luật** trên 5 trường kẻ tấn công điều khiển được: URL, Body, Cookie, Referer, User-Agent.
4. **Quyết định**, theo thứ tự ưu tiên:
   - DoS → **429** (kèm `Retry-After`)
   - Đang khẩn cấp DDoS và IP lạ → **429**
   - Vi phạm luật nội dung → **403**
   - Sạch → **200**
5. **Chế tài** cho IP vi phạm, rồi **ghi nhận** vào lịch sử và `realtime_access.log`.

---

## 6 loại tấn công và chế tài

| Loại | Cách phát hiện | Phản hồi | Chế tài |
|---|---|:---:|---|
| **SQL Injection** | Regex: `' OR '1'='1`, `OR 1=1`, `AND 1=1`, `UNION SELECT`, `admin'--`, `' \|\| '`, `; DROP`, `SLEEP(`, `@@version`... | 403 | +1 điểm vi phạm |
| **XSS** | Regex: `<script`, `<iframe`, `onerror=`, `onload=`, `onmouseover=`, `javascript:`, `document.cookie`... | 403 | +1 điểm vi phạm |
| **Công cụ quét** | User-Agent chứa `sqlmap`, `nikto`, `nmap`, `gobuster`, `wpscan`... | 403 | **Khoá IP ngay** |
| **Dò đường dẫn nhạy cảm** | Nguyên đoạn đường dẫn `/.env`, `/.git`, `/admin`, `/backup`... (`/administrator-guide` không bị chặn nhầm) | 403 | +1 điểm vi phạm |
| **DoS** | 1 IP gửi > 15 request trong cửa sổ trượt 10 giây | 429 | +1 điểm mỗi request vượt ngưỡng |
| **DDoS** | Tổng > 40 request **và** > 8 IP khác nhau trong 10 giây | 429 | **Chế độ khẩn cấp** |

**Khoá IP theo bậc:** đủ **3 điểm vi phạm trong 10 phút** thì khoá IP. Lần khoá thứ 1 / 2 / 3 trở đi kéo dài **5 / 15 / 60 phút**. IP đang bị khoá nhận 403 cho mọi request.

**Chế độ khẩn cấp DDoS:** bật khi vượt ngưỡng DDoS, tắt sau 10 giây lưu lượng trở lại bình thường. Trong thời gian khẩn cấp:
- **IP quen** (đã có request sạch trước khi tấn công bắt đầu ít nhất 10 giây) vẫn truy cập bình thường.
- **IP lạ** nhận 429.

Nhờ vậy người dùng thật không bị chặn nhầm, còn bot lọt được vài request đầu đợt flood cũng không được tính là IP quen. DDoS không cộng điểm vì bot đổi IP liên tục.

Toàn bộ ngưỡng nằm trong `ips/config.py`. Các ngưỡng đang để thấp cho dễ demo bằng tay.

### Tự bảo vệ của IPS
- `/__unban` (mở khoá IP) và `/__reset` (xoá dữ liệu) chỉ nhận **POST** từ **chính máy chạy server**, kèm header `X-IPS-Admin: 1` (chống CSRF).
- `X-Forwarded-For` chỉ được tin khi request đến từ máy chạy server. Máy khác không giả IP để né DoS hay né khoá được.
- Body được quét toàn bộ; body > 1 MB bị từ chối (**413**).
- Mọi đường dẫn đều đi qua IPS, kể cả đường dẫn chứa ký tự xuống dòng (`/a%0Ab`).
- Giao diện giám sát hiển thị payload của kẻ tấn công bằng `textContent`, nên không tự dính XSS.

---

## Hướng dẫn chạy

```powershell
pip install -r requirements.txt
python server.py
```

Mở giao diện giám sát: **http://127.0.0.1:5000/__monitor**

Giao diện gồm:
- Thẻ tổng và 6 thẻ theo loại tấn công (bấm thẻ để lọc).
- Biểu đồ lưu lượng 60 giây.
- Cảnh báo gần nhất.
- Danh sách IP bị khoá, có nút mở khoá.
- Bảng request có lọc theo loại/kết quả, tìm kiếm, và xem chi tiết từng request.

### Demo tự động
Mở terminal thứ hai:
```powershell
python attack_demo.py
```
Kịch bản (khoảng 30 giây):
1. IP quen truy cập bình thường.
2. SQLi/XSS bị chặn 403.
3. Một IP thử SQLi 3 lần thì bị khoá.
4. Dò `/.env`, `/.git` bị chặn và khoá; `/administrator-guide` vẫn qua.
5. sqlmap bị khoá ngay.
6. DoS: 15 request đầu 200, rồi 429, rồi bị khoá.
7. DDoS: bot nhận 429 trong khi IP quen vẫn nhận 200.

### Thử bằng tay
- **Trình duyệt:** `http://127.0.0.1:5000/product?id=1' OR '1'='1` (403). Nhấn F5 liên tục khoảng 20 lần để thấy 429.
- **Postman:**
  - `POST /login` với body `{"user": "admin'--"}`
  - Header `User-Agent: sqlmap/1.7`
  - Header `Cookie: session=<script>alert(1)</script>`
  - Header `X-Forwarded-For: 1.2.3.4` để giả lập IP khác
- **cURL:** `curl.exe -A "sqlmap/1.5" "http://127.0.0.1:5000/"`

> Bị khoá chính IP của mình (127.0.0.1) khi thử bằng tay? Mở khoá ngay trên giao diện, hoặc bấm "Xoá dữ liệu demo".

### Kiểm thử tự động
```powershell
python -m unittest discover -s tests -t . -v
```

---

## Mã HTTP hệ thống trả về

| Mã | Ý nghĩa |
|---|---|
| `200 OK` | Request sạch, được cho qua |
| `403 Forbidden` | Chặn vì nội dung (SQLi, XSS, công cụ quét, dò đường dẫn), hoặc IP đang bị khoá |
| `429 Too Many Requests` | Chặn vì tần suất (DoS), hoặc IP lạ trong lúc khẩn cấp DDoS; kèm `Retry-After` |
| `413 Payload Too Large` | Body lớn hơn 1 MB |

---

## Giới hạn và hướng phát triển

- **Ba loại tấn công không đi qua web request nên IPS không thấy:**
  - DNS Spoofing: phòng bằng DNSSEC, HSTS.
  - Session Hijacking trên đường truyền: phòng bằng TLS và cookie `Secure`/`HttpOnly`.
  - Mã độc/webshell trên máy chủ: phòng bằng quét file upload, thư mục `noexec`.
- **Phát hiện theo chữ ký luôn có thể bị lách bằng biến thể mới.** Phòng thủ gốc vẫn phải nằm trong code ứng dụng: prepared statement, mã hoá đầu ra, CSP.
- **Trạng thái nằm trong RAM:** khởi động lại server là mất danh sách khoá.
- **Hướng phát triển:**
  - Khoá IP ở tường lửa hệ điều hành (`netsh` / `iptables`).
  - Lưu trạng thái vào Redis.
  - Thử thách CAPTCHA thay cho 429 khi DDoS.
  - Cảnh báo qua Telegram.
