# -*- coding: utf-8 -*-
"""
Gói ips: lõi của hệ thống ngăn chặn xâm nhập (IPS) cho ứng dụng web.

  config.py     mọi ngưỡng, thời gian khoá
  rules/        6 luật phát hiện, mỗi loại tấn công một file
  engine.py     pipeline xử lý 1 request: kiểm tra khoá -> chạy luật -> quyết định -> ghi nhận
  sanctions.py  chế tài: điểm vi phạm, khoá IP theo bậc, chế độ khẩn cấp DDoS
  storage.py    lịch sử request, cảnh báo, file log
"""
