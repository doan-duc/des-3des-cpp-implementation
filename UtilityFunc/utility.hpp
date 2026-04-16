#pragma once

#include "../DataTypes/Key_types.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace des_sim {

// ========== HIEU CHINH AND UTILITY FUNCTIONS ==========

// Mau sac ANSI
extern const std::string BOLD;
extern const std::string GREEN;
extern const std::string CYAN;
extern const std::string YELLOW;
extern const std::string RED;
extern const std::string RESET;

// In text voi mau
void cprint(const std::string& text, const std::string& color = "");

// Chuyen string thanh uppercase
std::string to_upper_ascii(std::string s);

// Nhap tuy chon tu user (validate trong danh sach)
std::string read_choice(const std::string& prompt, const std::vector<std::string>& valid);

// Nhap yes/no tuy chon
bool read_yes_no(const std::string& prompt);

// Nhap khoa DES tu user
DESKey input_des_key(const std::string& label);

// Nhap khoa 3DES hoac DES tu user
TripleDESKey input_key_prompt(bool use_3des);

// Chon che do ma hoa (ECB hoac CBC)
std::string get_mode_choice();

// Nhap IV (Initialization Vector)
uint64_t get_iv_input();

// Doc du lieu dau vao de ma hoa (text hoac hex)
std::vector<uint8_t> read_encrypt_input(bool& ok);

// Kiem tra xem du lieu co phai UTF-8 hop le khong
bool is_valid_utf8(const std::vector<uint8_t>& data);

// ========== HEX CONVERSION FUNCTIONS ==========

// Chuyen vector<uint8_t> thanh hex string
std::string bytes_to_hex(const std::vector<uint8_t>& data);

// Chuyen hex string thanh vector<uint8_t>
std::vector<uint8_t> hex_to_bytes(const std::string& hex);

// San sach hex string (loai bo ky tu khong hop le)
std::string sanitize_hex(const std::string& input);

}  // namespace des_sim
