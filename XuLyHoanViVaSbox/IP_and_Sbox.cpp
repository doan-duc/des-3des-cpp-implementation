#include "IP_and_Sbox.hpp"
#include "Tables.hpp"

#include <iostream>

using namespace std;

// Các hàm xử lý hoán vị và S-box cho DES
namespace des_sim {

// Hàm để hoán vị bit theo các bảng cho trước
uint64_t permute_bits(uint64_t bits, const vector<int>& table, int input_size) {
    uint64_t result = 0;
    int output_size = static_cast<int>(table.size());
    for (int i = 0; i < output_size; ++i) {
        int bit_pos = table[i];
        // Lấy bit từ vị trí giá trị của table[i], lấy giá trị của bit đó
        uint64_t bit_val = (bits >> (input_size - bit_pos)) & 1ULL;
        result |= bit_val << (output_size - 1 - i);
    }
    return result;
}

// Hàm để thực hiện hoán vị IP và FP
uint64_t initial_permutation(uint64_t block_64) {
    return permute_bits(block_64, vector<int>(IP.begin(), IP.end()), 64);
}
uint64_t final_permutation(uint64_t block_64) {
    return permute_bits(block_64, vector<int>(FP.begin(), FP.end()), 64);
}

// Hàm thực hiện một vòng Feistel, trả về cặp (L', R') sau khi áp dụng hàm F và hoán vị
pair<uint32_t, uint32_t> feistel_round(
    uint32_t L, uint32_t R, uint64_t subkey, const function<uint32_t(uint32_t, uint64_t)>& f_fn, int round_num, bool verbose
) {
    if (verbose) cout << "Round " << round_num << " L=" << hex << L << " R=" << R << " K=" << subkey << "\n";
    uint32_t f_result = f_fn(R, subkey);
    return {R, static_cast<uint32_t>(L ^ f_result)};
}

// Hàm tra cứu S-box
int sbox_lookup(int sbox_index, uint8_t six_bits) {
    int row = (((six_bits >> 5) & 1) << 1) | (six_bits & 1);
    int col = (six_bits >> 1) & 0xF;
    return SBOXES[sbox_index][row][col];
}

//
uint32_t feistel_f(uint32_t R, uint64_t subkey) {
    //Mở rộng R từ bảng E
    uint64_t r_expanded = permute_bits(R, E_TABLE, 32);
    uint64_t xor_result = r_expanded ^ subkey;
    // Cho qua S_box
    uint32_t s_output = sbox_substitute(xor_result);
    return static_cast<uint32_t>(permute_bits(s_output, vector<int>(P_TABLE.begin(), P_TABLE.end()), 32));
    //Hoán vị kết quả qua bảng P và trả về
}

// Hàm thay thế 48 bit qua S-box thành 32 bit
uint32_t sbox_substitute(uint64_t bits_48) {
    uint32_t result = 0;
    for (int i = 0; i < 8; ++i) {
        int shift = (7 - i) * 6;
        uint8_t six_bits = static_cast<uint8_t>((bits_48 >> shift) & 0x3F);
        int four_bits = sbox_lookup(i, six_bits);
        result |= static_cast<uint32_t>(four_bits) << ((7 - i) * 4);
    }
    return result;
}

}  // namespace des_sim
