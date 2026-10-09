// Giao diện giám sát IPS: lấy /__data mỗi 1,5 giây rồi vẽ lại.
// Dữ liệu chứa payload của kẻ tấn công, nên MỌI nội dung đều đưa vào bằng textContent
// (hàm el bên dưới), không bao giờ ghép chuỗi HTML.

const KET_QUA = {
  cho_qua: "200 Cho qua",
  chan_403: "403 Chặn",
  chan_429: "429 Quá tần suất",
  ip_bi_khoa: "403 IP bị khoá",
};
// Thao tác quản trị: bắt buộc POST + header X-IPS-Admin (xem chi_quan_tri trong server.py)
const QUAN_TRI = { method: "POST", headers: { "X-IPS-Admin": "1", "Content-Type": "application/json" } };

let DATA = null;
let bietId = 0;
let chart = null;
let daTaoTheLoai = false;

const $ = (id) => document.getElementById(id);

function el(tag, props = {}, ...con) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of con) if (c != null) e.append(c);   // chuỗi được append như text node
  return e;
}

function thayNoiDung(cha, ...con) {
  cha.replaceChildren(...con);
}

// ---------------- Biểu đồ ----------------
function taoBieuDo() {
  if (typeof Chart === "undefined") return;   // thiếu Chart.js: bỏ biểu đồ, phần còn lại vẫn chạy
  const nhom = (label, mau) => ({ label, data: [], backgroundColor: mau, borderRadius: 2 });
  chart = new Chart($("bieuDo"), {
    type: "bar",
    data: { labels: [], datasets: [nhom("Cho qua", "#2f7d4f"), nhom("Chặn 403", "#b42318"), nhom("Chặn 429", "#d97706")] },
    options: {
      animation: false, maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12 } } },
      scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 10 } },
                y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}

function veBieuDo(bd) {
  if (!chart) return;
  chart.data.labels = bd.nhan;
  chart.data.datasets[0].data = bd.cho_qua;
  chart.data.datasets[1].data = bd.chan_403;
  chart.data.datasets[2].data = bd.chan_429;
  chart.update();
}

// ---------------- Thẻ thống kê ----------------
function taoTheLoai(luat) {
  const khung = $("theLoai");
  for (const l of luat) {
    khung.append(el("button", { "data-ma": l.ma, title: "Bấm để lọc theo " + l.ten, onclick: () => locTheoLoai(l.ma) },
      el("span", { class: "so", id: "dem-" + l.ma, text: "0" }),
      el("span", { class: "ten", text: l.ten })));
    $("fLoai").append(el("option", { value: l.ma, text: l.ten }));
  }
  daTaoTheLoai = true;
}

function locTheoLoai(ma) {
  $("fLoai").value = $("fLoai").value === ma ? "all" : ma;
  veBang();
}

function veThe(d) {
  $("sTong").textContent = d.tong;
  $("sChoQua").textContent = d.cho_qua;
  $("sBiChan").textContent = d.bi_chan;
  $("sKhoa").textContent = d.ds_khoa.length;
  for (const l of d.luat) $("dem-" + l.ma).textContent = d.theo_loai[l.ma] || 0;
  const kc = $("khanCap");
  kc.textContent = "Khẩn cấp DDoS: " + (d.khan_cap.bat ? "BẬT" : "TẮT");
  kc.className = "pill " + (d.khan_cap.bat ? "pill-on" : "pill-off");
}

// ---------------- Cảnh báo ----------------
function veCanhBao(ds) {
  if (!ds.length) return thayNoiDung($("dsCanhBao"), el("li", { class: "trong", text: "Chưa có cảnh báo nào" }));
  thayNoiDung($("dsCanhBao"), ...ds.map((c) =>
    el("li", { class: c.muc }, el("span", { class: "tg", text: c.tg }), c.noi_dung)));
}

// ---------------- IP bị khoá ----------------
function dongHo(giay) {
  giay = Math.max(0, Math.round(giay));
  return Math.floor(giay / 60) + ":" + String(giay % 60).padStart(2, "0");
}

function veKhoa(ds, bayGio) {
  if (!ds.length) {
    return thayNoiDung($("tbKhoa"), el("tr", {}, el("td", { colspan: "5", class: "trong", text: "Không có IP nào đang bị khoá" })));
  }
  thayNoiDung($("tbKhoa"), ...ds.map((k) => el("tr", {},
    el("td", { class: "mono", text: k.ip }),
    el("td", { text: k.ly_do }),
    el("td", { text: "Lần " + k.lan }),
    el("td", { class: "mono", text: dongHo(k.het_han - bayGio) }),
    el("td", {}, el("button", { class: "btn btn-nho", text: "Mở khoá", onclick: () => moKhoa(k.ip) })))));
}

async function moKhoa(ip) {
  const r = await fetch("/__unban", { ...QUAN_TRI, body: JSON.stringify({ ip }) });
  if (!r.ok) alert("Không có quyền mở khoá (chỉ thao tác được trên máy chạy server)");
  capNhat();
}

// ---------------- Bảng request ----------------
function nhanPhanLoai(r) {
  if (!r.loai.length) return [el("span", { class: "nhan", text: "Bình thường" })];
  return r.loai.map((x) => el("span", { class: "nhan " + x.muc_do, text: x.ten }));
}

function khopLoc(r) {
  const loai = $("fLoai").value, kq = $("fKetQua").value;
  const tim = $("fTim").value.trim().toLowerCase();
  if (loai === "binh_thuong" && r.loai.length) return false;
  if (loai !== "all" && loai !== "binh_thuong" && !r.loai.some((x) => x.ma === loai)) return false;
  if (kq !== "all" && r.ket_qua !== kq) return false;
  if ($("fTanCong").checked && r.status === 200) return false;
  if (tim && ![r.ip, r.url, r.agent].some((s) => (s || "").toLowerCase().includes(tim))) return false;
  return true;
}

function veBang() {
  if (!DATA) return;
  const rows = DATA.rows.filter(khopLoc);
  document.querySelectorAll("#theLoai button").forEach((b) =>
    b.classList.toggle("dang-loc", b.dataset.ma === $("fLoai").value));
  $("demKq").textContent = `Hiển thị ${rows.length}/${DATA.rows.length} request gần nhất`;
  if (!rows.length) {
    return thayNoiDung($("tbReq"), el("tr", {}, el("td", { colspan: "7", class: "trong", text: "Không có request nào khớp bộ lọc" })));
  }
  thayNoiDung($("tbReq"), ...rows.map((r) => el("tr", { class: bietId && r.id > bietId ? "moi" : "", onclick: () => xemChiTiet(r) },
    el("td", { class: "mono", text: r.tg }),
    el("td", { class: "mono", text: r.ip }),
    el("td", { text: r.method }),
    el("td", { class: "url", title: r.url, text: r.url }),
    el("td", {}, el("span", { class: "kq kq-" + r.ket_qua, text: KET_QUA[r.ket_qua] })),
    el("td", {}, ...nhanPhanLoai(r)),
    el("td", { class: "che-tai", text: r.che_tai || r.ghi_chu || "" }))));
}

// ---------------- Chi tiết ----------------
function xemChiTiet(r) {
  const dong = (ten, ...gt) => [el("dt", { text: ten }), el("dd", {}, ...gt)];
  const luat = r.loai.length
    ? r.loai.map((x) => el("div", { class: "luat" }, el("b", { text: x.ten + " (" + x.muc_do + ")" }), el("br"), x.chi_tiet))
    : ["Không vi phạm luật nào"];
  thayNoiDung($("ctiet"),
    ...dong("Thời gian", r.tg),
    ...dong("IP", r.ip),
    ...dong("Method", r.method),
    ...dong("URL", r.url),
    ...dong("Body", r.body || "(trống)"),
    ...dong("Cookie", r.cookie || "(trống)"),
    ...dong("Referer", r.referer || "(trống)"),
    ...dong("User-Agent", r.agent || "(trống)"),
    ...dong("Kết quả", el("span", { class: "kq kq-" + r.ket_qua, text: KET_QUA[r.ket_qua] })),
    ...dong("Luật vi phạm", ...luat),
    ...dong("Chế tài", r.che_tai || "Không"),
    ...dong("Điểm vi phạm", `${r.diem} điểm (đủ 3 điểm thì khoá IP)`),
    ...(r.ghi_chu ? dong("Ghi chú", r.ghi_chu) : []));
  $("overlay").classList.add("mo");
}

function dongChiTiet() {
  $("overlay").classList.remove("mo");
}

// ---------------- Cập nhật ----------------
async function capNhat() {
  try {
    const d = await (await fetch("/__data")).json();
    DATA = d;
    if (!daTaoTheLoai) taoTheLoai(d.luat);
    veThe(d);
    veBieuDo(d.bieu_do);
    veCanhBao(d.canh_bao);
    veKhoa(d.ds_khoa, d.bay_gio);
    veBang();
    bietId = d.rows.length ? d.rows[0].id : 0;
    $("live").className = "live";
    $("live").textContent = "● Đang nhận dữ liệu";
  } catch (e) {
    $("live").className = "live off";
    $("live").textContent = "● Mất kết nối server";
  }
}

async function xoaDuLieu() {
  if (!confirm("Xoá toàn bộ lịch sử, cảnh báo, điểm vi phạm và danh sách IP bị khoá?")) return;
  const r = await fetch("/__reset", QUAN_TRI);
  if (!r.ok) alert("Không có quyền (chỉ thao tác được trên máy chạy server)");
  bietId = 0;
  capNhat();
}

function boLoc() {
  $("fLoai").value = "all";
  $("fKetQua").value = "all";
  $("fTim").value = "";
  $("fTanCong").checked = false;
  veBang();
}

["fLoai", "fKetQua", "fTanCong"].forEach((id) => $(id).addEventListener("change", veBang));
$("fTim").addEventListener("input", veBang);
$("btnBoLoc").addEventListener("click", boLoc);
$("btnReset").addEventListener("click", xoaDuLieu);
$("btnDong").addEventListener("click", dongChiTiet);
$("overlay").addEventListener("click", (e) => { if (e.target.id === "overlay") dongChiTiet(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") dongChiTiet(); });

taoBieuDo();
capNhat();
setInterval(capNhat, 1500);
