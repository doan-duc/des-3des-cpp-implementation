# Mô Phỏng Hệ Thống Mã Hóa DES và 3DES

Đây là dự án mô phỏng hoạt động mã hóa và giải mã theo chuẩn DES (Data Encryption Standard) và 3DES (Triple DES), được triển khai bằng C++ dưới dạng giao diện dòng lệnh (CLI).

## 1. Phân Công Nhiệm Vụ

Bảng phân công công việc chi tiết của nhóm gồm 5 thành viên:

| Họ và Tên | MSSV | Phân Công Công Việc |
| :--- | :--- | :--- |
| Đoàn Sinh Đức | 20234000 | Phụ trách module DES (thư mục DES), phần Test (thư mục Test) và chương trình chính main.cpp; đồng thời tổng hợp, kết nối các module để chương trình chạy đồng bộ. |
| Nguyễn Minh Đức | 20234001 | Phụ trách thư mục DataTypes và UtilityFunc, bao gồm xử lý kiểu dữ liệu block/key, bộ đệm (padding), và các hàm hỗ trợ nhập xuất/chuyển đổi dữ liệu. |
| Hoàng Mạnh Dũng | 20234002 | Phụ trách thư mục ModeTDES, triển khai luồng mã hóa/giải mã 3DES và các chế độ vận hành khối (ECB, CBC). |
| Vũ Trí Dũng | 20234003 | Phụ trách thư mục XuLyHoanViVaSbox, xây dựng các bảng và hàm hoán vị (IP, FP, E, P) và xử lý S-Box theo đúng chuẩn DES. |
| Nguyễn Đoàn Thùy Dương | 20234004 | Phụ trách thư mục Subkeys, triển khai Key Schedule (PC-1, PC-2, left shift) để sinh 16 khóa con phục vụ DES/3DES. |

---

## 2. Mô Tả Dự Án

Dự án là hệ thống mô phỏng thuật toán mã hóa cổ điển DES và 3DES phục vụ học tập, nghiên cứu, và bài tập lớn môn An Toàn Thông Tin.

### Các thành phần kỹ thuật chính

- Hỗ trợ đầy đủ DES và Triple-DES (2-key/3-key tùy theo dữ liệu khóa).
- Hỗ trợ mã hóa/giải mã theo chế độ ECB và CBC.
- Có xử lý PKCS#7 padding cho dữ liệu không tròn 64-bit block.
- Có bộ kiểm thử KAT (Known Answer Tests) theo bộ vector NIST trong thư mục KAT_TDES.
- Cấu trúc module hóa rõ ràng theo từng nhóm chức năng để dễ bảo trì và debug.

### Hướng Dẫn Chạy Dự Án

#### Chạy chương trình chính (CLI)

```bash
git clone https://github.com/doan-duc/des-3des-python-implementation.git
cd des-3des-python-implementation/CodeCpp
g++ main.cpp -o main
.\main
```

---

## 3. Cấu Trúc Thư Mục Dự Án

```text
CodeCpp/
|
|-- main.cpp
|
|-- DataTypes/
|   |-- Block_types.cpp
|   |-- Block_types.hpp
|   |-- Key_types.cpp
|   `-- Key_types.hpp
|
|-- DES/
|   |-- DES.cpp
|   `-- DES.hpp
|
|-- ModeTDES/
|   |-- TDES.cpp
|   `-- TDES.hpp
|
|-- Subkeys/
|   |-- DES_subkeys.cpp
|   |-- DES_subkeys.hpp
|   |-- TDES_subkeys.cpp
|   `-- TDES_subkeys.hpp
|
|-- UtilityFunc/
|   |-- utility.cpp
|   `-- utility.hpp
|
|-- XuLyHoanViVaSbox/
|   |-- IP_and_Sbox.cpp
|   |-- IP_and_Sbox.hpp
|   `-- Tables.hpp
|
|-- Test/
|   |-- inout.cpp
|   |-- inout.hpp
|   `-- test_KAT.cpp
|
|-- KAT_TDES/
`-- tdesmmt/
```

---

## 4. Demo Chạy Chương Trình

Phần này minh họa một phiên chạy thực tế từ lúc nhập lựa chọn đến khi nhận kết quả mã hóa.

### 4.1. Thông tin đầu vào demo

- Chức năng: Mã hóa văn bản
- Thuật toán: DES (không bật 3DES)
- Mode: ECB
- Khóa DES: `133457799BBCDFF1`
- Plaintext (Text): `HELLO DES`

### 4.2. Phiên chạy trên CLI

```text
C:\des-3des-python-implementation\CodeCpp> .\main

============================================
        HE THONG MO PHONG DES / 3DES
============================================
  1. Ma hoa van ban (Text -> Hex)
  2. Giai ma van ban (Hex -> Text)
  0. Thoat

Lua chon cong viec: 1
  Su dung 3DES? (y/n): n
  Nhap khoa DES (16 ky tu hex):
  > 133457799BBCDFF1

  Chon che do ma hoa (Block Mode):
  1. ECB (Electronic Codebook)
  2. CBC (Cipher Block Chaining)
Lua chon: 1

  Ban muon nhap gi?
  1. Van ban (Text/String)
  2. Chuoi Hex
Lua chon: 1
  Nhap van ban can ma hoa: HELLO DES

--- KET QUA MA HOA ---
  Che do         : ECB
  Ciphertext (H) : D67AF4DF0488B0373F6139AE5DDDE941
  Do dai         : 16 bytes (2 blocks)
  Status: [Smart Padding] Du lieu le -> Da dem PKCS#7.
```

## 5. Tổng Kết

Dự án đã được chia nhiệm vụ rõ ràng theo từng module, đảm bảo mỗi thành viên có phạm vi trách nhiệm cụ thể. Hệ thống đã hoạt động ổn định với CLI, hỗ trợ DES/3DES đầy đủ, và đã vượt các bộ test KAT trong thư mục KAT_TDES.

Cảm ơn cô đã giảng dạy và hướng dẫn chúng em ạ !
