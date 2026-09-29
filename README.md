# He thong giam sat & phat hien tan cong ung dung web

De tai mon **Bao mat ung dung va he thong**.
He thong doc **file log** cua web server (Nginx/Apache) roi phat hien dau hieu tan cong.
Vi chi doc log nen **ap dung duoc cho moi web** (PHP, Node, Java...) ma khong can sua code web.

## Cac loai tan cong phat hien duoc

| Loai tan cong (trong bai hoc) | Cach phat hien |
|---|---|
| 1. DoS | 1 IP gui qua nhieu request trong 1 phut (nguong: 100) |
| 2. DDoS | Tong request tang vot + rat nhieu IP khac nhau cung luc |
| 5. SQL Injection | Do khop mau: `OR 1=1`, `UNION SELECT`, `SLEEP()`, `--`... |
| (Them) XSS | Mau: `<script>`, `onerror=`, `document.cookie` |
| (Them) Cong cu quet | User-Agent: sqlmap, nikto, nmap... |
| (Them) Do tim duong dan | `/wp-admin`, `/.env`, `/phpmyadmin`... |

**Luu y trong bao cao** (3 loai kho lam bang log web, nen trinh bay ly thuyet / mo rong):
- **Gia mao DNS**: xay ra phia nguoi dung, server khong thay trong log. Phong chong: DNSSEC, HTTPS, HSTS.
- **Session Hijacking**: can dat reverse proxy de doc cookie, so sanh IP/User-Agent theo tung session.
- **Trojan/Virus/Worm**: la ma doc tren may, khong phai request HTTP. Phan lien quan web: quet file upload (ClamAV), phat hien webshell.

## Cau truc thu muc

| File | Chuc nang |
|---|---|
| `parser.py` | Doc file log -> tach thanh IP, thoi gian, URL, code... |
| `detect.py` | Cac luat phat hien tan cong (chinh nguong o day) |
| `monitor.py` | Chay tren terminal: in canh bao (de chup man hinh) |
| `dashboard.py` | Trang web hien thi bieu do + bang canh bao |
| `make_sample_log.py` | Tao log mau de demo (khong tan cong web that) |

## Cach chay

```bash
# 1. Cai thu vien
pip3 install flask

# 2. Tao log mau de demo
python3 make_sample_log.py

# 3a. Xem ket qua tren terminal
python3 monitor.py access.log

# 3b. Hoac xem tren trang web (dep hon)
python3 dashboard.py
# -> mo trinh duyet: http://127.0.0.1:5000
```

## Dung voi web that (khong bat buoc, phan nang cao)

Thay vi dung log mau, tro `LOG_FILE` trong `dashboard.py` toi log that:
- Nginx: `/var/log/nginx/access.log`
- Apache: `/var/log/apache2/access.log`

## Goi y cau truc bao cao

1. **Gioi thieu**: van de - web bi tan cong, nhu cau giam sat.
2. **Co so ly thuyet**: mo ta 6 loai tan cong, khai niem WAF/SIEM/log.
3. **Phan tich & thiet ke**: so do he thong, giai thich vi sao doc log ap dung duoc moi web.
4. **Cai dat**: giai thich tung file va tung luat phat hien.
5. **Thu nghiem (demo)**: chay `make_sample_log.py` + chup man hinh terminal va dashboard.
6. **Danh gia**: uu diem, han che (co the bi bypass bang ma hoa, bao nham...), so sanh voi ModSecurity.
7. **Ket luan & huong phat trien**: them tu dong chan IP, canh bao Telegram, module DNS...

## Huong nang cao (neu con thoi gian)

- Tu dong chan IP xau (ghi vao iptables hoac danh sach den cua Nginx).
- Gui canh bao qua Telegram / Email.
- Doc log truc tiep theo thoi gian thuc (tail -f).
- So sanh ket qua voi ModSecurity + OWASP CRS.
