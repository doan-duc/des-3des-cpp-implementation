#pragma once
#include "../DataTypes/Key_types.hpp"
#include <map>
#include <string>
using namespace std;

namespace des_sim {
// Khai bao ham ma hoa file.
// input_path la duong dan file dau vao can ma hoa.
// output_path la duong dan file dau ra sau khi ma hoa.
// key la bo khoa DES hoac 3DES duoc su dung trong qua trinh ma hoa.
// use_3des cho biet co bat che do 3DES hay khong.
// Ham tra ve map thong ke kich thuoc du lieu va thoi gian xu ly.
map<string, double> encrypt_file(
    const string& input_path, const string& output_path, const TripleDESKey& key, bool use_3des = false
);

// Khai bao ham giai ma file.
// input_path la duong dan file ciphertext dau vao.
// output_path la duong dan file plaintext dau ra sau khi giai ma.
// key la bo khoa DES hoac 3DES duoc su dung trong qua trinh giai ma.
// use_3des cho biet co bat che do 3DES hay khong.
// Ham tra ve map thong ke kich thuoc du lieu va thoi gian xu ly.
map<string, double> decrypt_file(
    const string& input_path, const string& output_path, const TripleDESKey& key, bool use_3des = false
);
}
