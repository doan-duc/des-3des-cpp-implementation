#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

namespace des_sim {

struct DESBlock {
    uint64_t value{0};
    explicit DESBlock(uint64_t v = 0) : value(v) {}

    array<uint8_t, 8> to_bytes() const;
    static DESBlock from_bytes(const vector<uint8_t>& data, size_t offset = 0);
    string to_bin_str() const;
    string to_hex_str() const;
};

vector<DESBlock> split_into_blocks(const vector<uint8_t>& data);
vector<uint8_t> blocks_to_bytes(const vector<DESBlock>& blocks);
vector<uint8_t> pkcs7_pad(const vector<uint8_t>& data, uint8_t block_size = 8);
vector<uint8_t> pkcs7_unpad(const vector<uint8_t>& data, uint8_t block_size = 8);

}  // namespace des_sim