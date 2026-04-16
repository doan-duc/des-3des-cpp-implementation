#include "TDES.hpp"
#include "../DES/DES.hpp"

#include <chrono>
#include <stdexcept>

using namespace std;

namespace des_sim {

// Hàm mã hóa một khối với Triple DES: Encrypt với K1, Decrypt với K2, Encrypt với K3
DESBlock triple_des_encrypt_block(const DESBlock& plaintext_block, const TripleDESKey& triple_key, bool verbose) {
    DESBlock step1 = des_cipher(plaintext_block, triple_key.k1, true, verbose);
    DESBlock step2 = des_cipher(step1, triple_key.k2, false, verbose);
    DESBlock step3 = des_cipher(step2, triple_key.get_k3(), true, verbose);
    return step3;
}

// Hàm giải mã một khối với Triple DES: Decrypt với K3, Encrypt với K2, Decrypt với K1
DESBlock triple_des_decrypt_block(const DESBlock& ciphertext_block, const TripleDESKey& triple_key, bool verbose) {
    DESBlock step1 = des_cipher(ciphertext_block, triple_key.get_k3(), false, verbose);
    DESBlock step2 = des_cipher(step1, triple_key.k2, true, verbose);
    DESBlock step3 = des_cipher(step2, triple_key.k1, false, verbose);
    return step3;
}


// Hàm mã hóa dữ liệu với 3DES hoặc DES, có thể chọn chế độ CBC hoặc ECB
pair<vector<uint8_t>, double> encrypt_data(
    const vector<uint8_t>& plaintext, const TripleDESKey& key, bool use_3des, bool padding, const string& mode, uint64_t iv
) {
    auto start = chrono::high_resolution_clock::now();
    // Áp dụng padding 
    vector<uint8_t> padded = padding ? pkcs7_pad(plaintext) : plaintext;
    // Thêm điều kiện kiểm tra, nếu không padding mà dữ liệu không chia hết cho 8 thì lỗi 
    if (!padding && padded.size() % 8 != 0) throw invalid_argument("Input without padding must be divisible by 8");

    auto blocks = split_into_blocks(padded);
    vector<DESBlock> encrypted_blocks;
    // Khởi tạo biến pre_cipher để lưu giá trị khối trước đó trong chế độ CBC, với giá trị ban đầu bằng IV cho vào 
    uint64_t prev_cipher = iv;
    for (const auto& block : blocks) {
        DESBlock in = block;
        if (mode == "CBC") in = DESBlock(block.value ^ prev_cipher);   // Nếu là CBC thì mã hóa giá trị block XOR với biến pre_cipher
        DESBlock out = use_3des ? triple_des_encrypt_block(in, key) : des_cipher(in, key.k1, true, false);
        if (mode == "CBC") prev_cipher = out.value;  
        encrypted_blocks.push_back(out);
    }
    auto end = chrono::high_resolution_clock::now();
    return {blocks_to_bytes(encrypted_blocks), chrono::duration<double, milli>(end - start).count()};
}


// Hàm giải mã dữ liệu với 3DES hoặc DES, có thể chọn chế độ CBC hoặc ECB
pair<vector<uint8_t>, double> decrypt_data(
    const vector<uint8_t>& ciphertext, const TripleDESKey& key, bool use_3des, bool padding, const string& mode, uint64_t iv
) {
    auto start = chrono::high_resolution_clock::now();
    if (ciphertext.size() % 8 != 0) throw invalid_argument("Ciphertext length must be divisible by 8");
    auto blocks = split_into_blocks(ciphertext);
    vector<DESBlock> decrypted_blocks;
    uint64_t prev_cipher = iv;
    for (const auto& block : blocks) {
        DESBlock raw = use_3des ? triple_des_decrypt_block(block, key) : des_cipher(block, key.k1, false, false);
        DESBlock out = (mode == "CBC") ? DESBlock(raw.value ^ prev_cipher) : raw;
        if (mode == "CBC") prev_cipher = block.value;
        decrypted_blocks.push_back(out);
    }
    vector<uint8_t> plain = blocks_to_bytes(decrypted_blocks);
    if (padding) plain = pkcs7_unpad(plain);
    auto end = chrono::high_resolution_clock::now();
    return {plain, chrono::duration<double, milli>(end - start).count()};
}

}  // namespace des_sim
