#include "DES_subkeys.hpp"

#include <iomanip>
#include <iostream>

using namespace std;

namespace des_sim {
// Thực hiện hoán vị bit theo bảng 
uint64_t apply_permutation(uint64_t bits, const vector<int>& table, int input_size) {
    uint64_t result = 0;
    int output_size = static_cast<int>(table.size());
    for (int i = 0; i < output_size; ++i) {
        int bit_pos = table[i];
        int shift_in = input_size - bit_pos;
        uint64_t bit_val = (bits >> shift_in) & 1ULL;
        int shift_out = output_size - 1 - i;
        result |= bit_val << shift_out;
    }
    return result;
}
// Dịch trái xoay vòng giới hạn trong 28 bit
uint32_t left_circular_shift_28(uint32_t value, int shift) {
    constexpr uint32_t MASK_28 = 0x0FFFFFFF; // Đảm bảo chỉ có 28 bit được sử dụng
    // Thực hiện dịch trái xoay vòng
    return static_cast<uint32_t>(((value << shift) | (value >> (28 - shift))) & MASK_28);
}

// Sinh khóa con từ khóa chính, trả về vector 16 khóa con 48 bit
vector<uint64_t> generate_subkeys(uint64_t key, bool verbose) {
    if (verbose) cout << "\n  Source key (hex) : " << uppercase << hex << setw(16) << setfill('0') << key << "\n";
    uint64_t key_56 = apply_permutation(key, PC1, 64); // Hoán vị để bỏ các bit check đúng sai
    uint32_t C = static_cast<uint32_t>((key_56 >> 28) & 0x0FFFFFFF);
    uint32_t D = static_cast<uint32_t>(key_56 & 0x0FFFFFFF);
    vector<uint64_t> subkeys;
    subkeys.reserve(16);
    // Vòng lặp sinh khóa cho 16 vòng của thuật toán 
    for (int rnd = 0; rnd < 16; ++rnd) {
        int shift = SHIFT_SCHEDULE[rnd];
        // Thực hiện dịch trái xoay vòng cho cả nửa C và nửa D
        C = left_circular_shift_28(C, shift);
        D = left_circular_shift_28(D, shift);
        uint64_t CD = (static_cast<uint64_t>(C) << 28) | D;
        uint64_t subkey = apply_permutation(CD, PC2, 56);
        subkeys.push_back(subkey);
    }
    return subkeys;
}

}  // namespace des_sim
