#pragma once

#include "../DataTypes/Block_types.hpp"
#include "../DataTypes/Key_types.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using namespace std;

namespace des_sim {
DESBlock triple_des_encrypt_block(const DESBlock& plaintext_block, const TripleDESKey& triple_key, bool verbose = false);
DESBlock triple_des_decrypt_block(const DESBlock& ciphertext_block, const TripleDESKey& triple_key, bool verbose = false);
pair<vector<uint8_t>, double> encrypt_data(
    const vector<uint8_t>& plaintext, const TripleDESKey& key, bool use_3des = false, bool padding = true, const string& mode = "ECB", uint64_t iv = 0
);
pair<vector<uint8_t>, double> decrypt_data(
    const vector<uint8_t>& ciphertext, const TripleDESKey& key, bool use_3des = false, bool padding = true, const string& mode = "ECB", uint64_t iv = 0
);
}
