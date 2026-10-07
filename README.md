# Hệ thống Giám sát & Ngăn chặn Tấn công Ứng dụng Web (WAF / IPS & IDS)

Đề tài môn **Bảo mật ứng dụng và hệ thống**.

Dự án xây dựng giải pháp bảo mật ứng dụng web theo mô hình **Tường lửa ứng dụng web & Hệ thống ngăn chặn xâm nhập (WAF / IPS - Web Application Firewall & Intrusion Prevention System)** kết hợp **Hệ thống phát hiện xâm nhập (IDS)**, có khả năng:
1. **Chế độ Realtime (WAF / IPS Gateway)**: Đứng ở cửa tiếp nhận request, phân tích ngay tức thì, chặn đứng các request độc hại (**403 Forbidden / 429 Too Many Requests**) hoặc cho phép đi qua (**200 OK**), đồng thời hiển thị Dashboard trực tiếp.
2. **Chế độ Phân tích Log (Log Analysis IDS)**: Đọc file `access.log` chuẩn Nginx/Apache để thống kê và truy vết dấu vết tấn công mà không cần can thiệp vào mã nguồn web.

---

## 🛡️ Điểm nổi bật: Chuyển đổi linh hoạt giữa IPS và IDS

Ngay trên thanh header của Dashboard, hệ thống trang bị nút chuyển đổi chế độ một chạm:
* **🛡️ Chế độ IPS (Chặn chủ động - Active Defense)** *(Mặc định)*: Khi phát hiện vi phạm, hệ thống **chém đứt kết nối tại cửa**:
  * Tấn công nội dung (SQLi, XSS, Scanner, Dò file nhạy cảm): Trả về **`403 Forbidden`**.
  * Tấn công tần suất lưu lượng (DoS, DDoS): Trả về **`429 Too Many Requests`**.
* **👁️ Chế độ IDS (Giám sát thụ động - Passive Monitoring)**: Khi có tấn công, hệ thống **vẫn ghi nhận và cảnh báo màu đỏ**, nhưng cho request đi vào xử lý bình thường (**`200 OK`**) để phục vụ việc thu thập chứng cứ điều tra số (Forensics).

---

## 🎯 Ma trận Phát hiện & Cơ chế xử lý của IPS

| Loại tấn công | Kỹ thuật & Mẫu nhận diện | Phản hồi của IPS |
|---|---|:---:|
| **1. SQL Injection** | Regex dò cú pháp SQL: `' OR 1=1`, `UNION SELECT`, `SLEEP()`, `admin'--`, `information_schema`... Quét cả **URL, Body, Cookie, Referer, User-Agent**; chống lách bằng ký tự xuống dòng (`%0a`) | **`403 Forbidden`** |
| **2. Cross-Site Scripting (XSS)** | Regex dò thẻ HTML & Event JS: `<script>`, `onerror=`, `onload=`, `document.cookie`... (quét cùng các trường như SQLi) | **`403 Forbidden`** |
| **3. Công cụ quét lỗ hổng** | So khớp User-Agent với Blacklist: `sqlmap`, `nikto`, `nmap`, `dirbuster`, `gobuster`, `wpscan`... | **`403 Forbidden`** |
| **4. Dò tìm đường dẫn nhạy cảm** | Dò danh sách đường dẫn quản trị/file cấu hình: `/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`... So khớp **nguyên đoạn đường dẫn** (`/admin`, `/backup.zip` bị chặn, còn `/administrator-guide` thì không) | **`403 Forbidden`** |
| **5. DoS (Đơn nguồn)** | Realtime: **cửa sổ trượt 10s**, 1 IP gửi > 15 request/10s. Phân tích log: gom theo **từng phút**, 1 IP > 100 request/phút | **`429 Too Many Requests`** |
| **6. DDoS (Phân tán)** | Realtime: tổng > 40 request/10s **đồng thời** từ > 8 IP khác nhau. Phân tích log: > 300 request/phút từ > 50 IP | **`429 Too Many Requests`** |

> Hai chế độ dùng ngưỡng khác nhau: realtime để ngưỡng thấp cho dễ demo bằng tay, còn phân tích log dùng ngưỡng sát thực tế hơn. Vì vậy chạy `attack_demo.py` rồi phân tích lại `realtime_access.log` sẽ **không** ra DoS/DDoS (25–60 request chưa vượt 100/300 request/phút).

### 🔒 Tự bảo vệ của IPS
* **Endpoint quản trị** `/__toggle_mode` (tắt/bật IPS) và `/__reset` (xoá log) chỉ nhận **POST** từ **chính máy chạy server** và phải có header `X-IPS-Admin: 1` (chống CSRF). Request từ máy khác bị trả **403**.
* **`X-Forwarded-For`** chỉ được tin khi request đến từ chính máy chạy server (để `attack_demo.py`/Postman giả lập nhiều IP). Máy khác đổi header này cũng không né được luật DoS.
* **Body** được quét toàn bộ; body > 1 MB bị từ chối luôn (**413**).
* Mọi request realtime được ghi ra **`realtime_access.log`** (định dạng Nginx), tắt server không mất bằng chứng.

> **Lưu ý lý thuyết trong báo cáo** (3 dạng tấn công không thể bắt qua Web Log):
> * **Giả mạo DNS (DNS Spoofing)**: Xảy ra ở tầng phân giải tên miền phía client/ISP. Phòng chống: DNSSEC, HTTPS HSTS.
> * **Chiếm đoạt phiên (Session Hijacking)**: Tấn công trộm Cookie trên đường truyền mạng. Phòng chống: HTTPS TLS 1.3, Cookie `Secure` & `HttpOnly`.
> * **Trojan / Virus / Webshell trên máy chủ**: Là mã độc nhị phân chạy ngầm trong OS. Phòng chống: Quét file upload bằng ClamAV, phân quyền thư mục `noexec`.

---

## 📂 Cấu trúc thư mục dự án

| File | Vai trò kỹ thuật |
|---|---|
| **`server.py`** | **(Chính) Server WAF / IPS Realtime**: Tiếp nhận request, phân loại tức thì, chặn 403/429, cung cấp Dashboard sống tự cập nhật mỗi 1.5s và API chuyển đổi chế độ IDS/IPS |
| **`detect.py`** | **Trái tim hệ thống (Rule Engine)**: Chứa toàn bộ biểu thức chính quy (Regex) và luật đếm DoS/DDoS theo phút cho chế độ phân tích log (cửa sổ trượt 10s của realtime nằm trong `server.py`) |
| **`attack_demo.py`** | **Tool test tấn công tự động**: Bắn đa luồng thử nghiệm các loại request (Bình thường, SQLi, XSS, Scanner, DoS, DDoS), in rõ kết quả chặn của IPS |
| **`parser.py`** | Bóc tách định dạng Combined Log Format của Nginx/Apache thành Dictionary |
| **`monitor.py`** | Công cụ CLI: Đọc file log tĩnh và in báo cáo an ninh mạng ra Terminal |
| **`dashboard.py`** | Giao diện Web phân tích file log tĩnh có sẵn bộ lọc theo mã 2xx/3xx/4xx/5xx |
| **`make_sample_log.py`** | Sinh file `access.log` mẫu giả lập đầy đủ traffic thường lẫn traffic tấn công |
| **`test_ips.py`** | Kiểm thử tự động (15 test): luật phát hiện, chống chặn nhầm, chặn 403/429, bảo vệ endpoint quản trị, file log |
| **`static/chart.umd.min.js`** | Thư viện Chart.js lưu sẵn: demo không cần Internet |
| **`requirements.txt`** | Danh sách thư viện cần thiết (`flask==3.0.3`) |

---

## 🚀 Hướng dẫn chạy thử nghiệm

> Chạy kiểm thử tự động: `python -m unittest -v test_ips`

### CÁCH 1: Demo Realtime (Khuyên dùng khi thuyết trình / báo cáo)

#### Bước 1: Cài đặt thư viện
```powershell
pip install -r requirements.txt
```
*(Hoặc: `python -m pip install -r requirements.txt`)*

#### Bước 2: Khởi động Server IPS
```powershell
python server.py
```

#### Bước 3: Mở Web Dashboard giám sát
Truy cập vào trình duyệt:
👉 **`http://127.0.0.1:5000/__monitor`**

---

### 🧪 Các cách bắn request thử nghiệm (Test IPS)

#### Cách 1.1: Chạy script tự động (`attack_demo.py`)
Mở cửa sổ Terminal thứ 2 và chạy:
```powershell
python attack_demo.py
```
Terminal sẽ in rõ ràng từng request:
* `[200 OK - HỢP LỆ]: /products`
* `[403 BỊ IPS CHẶN]: /product?id=1' OR '1'='1`
* `[403 BỊ IPS CHẶN]: /comment?text=<script>alert(1)</script>`
* `[403 BỊ IPS CHẶN]: /admin`
* `[429 BỊ IPS CHẶN]: /` (khi DoS/DDoS kích hoạt)

#### Cách 1.2: Gõ trực tiếp trên Trình duyệt Web
Mở tab trình duyệt mới và gõ thử:
* SQLi: `http://127.0.0.1:5000/product?id=1' OR '1'='1`
* XSS: `http://127.0.0.1:5000/search?q=<script>alert(1)</script>`
* Dò file nhạy cảm: `http://127.0.0.1:5000/.env`
* Nhấn giữ phím **`F5` liên tục 20 lần** để thấy IPS kích hoạt chặn DoS với mã **429**!

#### Cách 1.3: Dùng Postman (Test Body POST & Header Scanner)
* **Gửi SQLi trong Body POST**: Method `POST`, URL `http://127.0.0.1:5000/login`, Body JSON: `{"user": "admin'--"}` ➜ Server quét thấy trong body và chặn **403**.
* **Giả mạo công cụ quét**: Thêm Header `User-Agent: sqlmap/1.7` ➜ Bị chặn **403**.
* **Giả lập IP**: Thêm Header `X-Forwarded-For: 123.45.67.89` (chỉ có tác dụng khi Postman chạy trên cùng máy với server).
* **SQLi/XSS trong Cookie**: Thêm Header `Cookie: session=<script>alert(1)</script>` ➜ Bị chặn **403**.

#### Cách 1.4: Dùng lệnh cURL trong Terminal
```powershell
curl.exe "http://127.0.0.1:5000/product?id=1'%20OR%201=1--"
curl.exe -A "sqlmap/1.5" "http://127.0.0.1:5000/"
```

---

### CÁCH 2: Phân tích File Log tĩnh (Offline Analysis)

Dành cho kịch bản phân tích file `access.log` thu thập từ máy chủ Nginx/Apache:

```powershell
# 1. Tạo file log mẫu (hoặc copy file access.log thật vào thư mục)
python make_sample_log.py

# 2. Xem báo cáo tổng kết trên dòng lệnh Terminal
python monitor.py access.log

# 3. Xem giao diện web quản lý và phân loại mã log
python dashboard.py
# -> Mở trình duyệt: http://127.0.0.1:5001  (cổng riêng, chạy song song được với server.py)

# 4. Phân tích lại log mà server realtime đã ghi
python monitor.py realtime_access.log
```

---

## 📑 Bảng tra cứu ý nghĩa mã HTTP trong hệ thống IPS

* **`200 OK`**: Request hợp lệ, IPS cho phép đi vào ứng dụng backend.
* **`403 Forbidden`**: **Bị IPS CHẶN** do phát hiện chữ ký độc hại (SQLi, XSS, Scanner, File nhạy cảm).
* **`429 Too Many Requests`**: **Bị IPS CHẶN TẦN SUẤT** do vượt ngưỡng lưu lượng DoS hoặc DDoS (Rate Limit).
* **`400 Bad Request`**: Payload tấn công bị dị dạng hoặc cú pháp lỗi.
* **`404 Not Found`**: Dò tìm đường dẫn không tồn tại (nhiều 404 từ 1 IP là dấu hiệu quét thư mục).
* **`500 Internal Server Error`**: Lỗi backend ứng dụng (SQLi khai thác sâu ép server bung lỗi).
* **`503 Service Unavailable`**: Server bị quá tải khi chịu đợt tấn công DDoS diện rộng.

---

## 🎓 Gợi ý bố cục Báo cáo & Thuyết trình đạt điểm cao

1. **Giới thiệu**: Thực trạng an ninh mạng ứng dụng web, nhu cầu giám sát và ngăn chặn chủ động.
2. **Cơ sở lý thuyết**:
   * Mô hình WAF / IPS (Inline) vs IDS (Sniffer).
   * Phân tích 6 kỹ thuật tấn công (SQLi, XSS, DoS, DDoS, Scanners, Directory Probing).
3. **Phân tích & Thiết kế hệ thống**:
   * Sơ đồ luồng xử lý gói tin (Pipeline 4 bước).
   * Thuật toán phân tích nội dung (Regex) và phân tích hành vi (Sliding Window).
4. **Cài đặt & Thực nghiệm**:
   * Demo chế độ IPS: Bắn payload ➜ Bị chặn 403 / 429 ➜ Bảng điều khiển ghi nhận đỏ.
   * Demo nút chuyển đổi IDS/IPS: Cho thấy sự khác biệt giữa mã 200 (chỉ giám sát) và mã 403 (chặn thật).
5. **Đánh giá & Hướng phát triển**:
   * Kỹ thuật vượt mặt (WAF Evasion): Double encoding, Case manipulation, chèn xuống dòng (`SELECT%0a*%0aFROM`, đã vá bằng cờ regex `(?s)`), giấu payload trong Cookie/Referer hoặc sau phần đầu của body (đã vá bằng cách quét mọi trường và toàn bộ body). Cách còn lách được: escape Unicode trong JSON (`'`), chèn comment SQL (`UN/**/ION`).
   * Hướng nâng cao: Tự động khóa IP vào tường lửa OS (`iptables` / `netsh`), tích hợp AI Anomaly Detection, cảnh báo qua Telegram Bot.
