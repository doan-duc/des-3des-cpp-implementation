#include "Block_types.hpp"

#include <iomanip>
#include <sstream>
#include <stdexcept>

using namespace std;

namespace des_sim {

array<uint8_t, 8> DESBlock::to_bytes() const {
	array<uint8_t, 8> out{};
	for (int i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>((value >> ((7 - i) * 8)) & 0xFFu);
	return out;
}

DESBlock DESBlock::from_bytes(const vector<uint8_t>& data, size_t offset) {
	if (data.size() < offset + 8) throw invalid_argument("DESBlock expects 8 bytes");
	uint64_t v = 0;
	for (size_t i = 0; i < 8; ++i) v = (v << 8) | data[offset + i];
	return DESBlock(v);
}

string DESBlock::to_bin_str() const {
	string s(64, '0');
	for (int i = 0; i < 64; ++i) s[i] = ((value >> (63 - i)) & 1ULL) ? '1' : '0';
	return s;
}

string DESBlock::to_hex_str() const {
	ostringstream oss;
	oss << uppercase << hex << setw(16) << setfill('0') << value;
	return oss.str();
}

vector<DESBlock> split_into_blocks(const vector<uint8_t>& data) {
	if (data.size() % 8 != 0) throw invalid_argument("Input length must be divisible by 8");
	vector<DESBlock> blocks;
	blocks.reserve(data.size() / 8);
	for (size_t i = 0; i < data.size(); i += 8) blocks.push_back(DESBlock::from_bytes(data, i));
	return blocks;
}

vector<uint8_t> blocks_to_bytes(const vector<DESBlock>& blocks) {
	vector<uint8_t> out;
	out.reserve(blocks.size() * 8);
	for (const auto& b : blocks) {
		const auto bytes = b.to_bytes();
		out.insert(out.end(), bytes.begin(), bytes.end());
	}
	return out;
}

vector<uint8_t> pkcs7_pad(const vector<uint8_t>& data, uint8_t block_size) {
	if (block_size == 0) throw invalid_argument("block_size must be > 0");
	uint8_t pad_len = static_cast<uint8_t>(block_size - (data.size() % block_size));
	vector<uint8_t> out = data;
	out.insert(out.end(), pad_len, pad_len);
	return out;
}

vector<uint8_t> pkcs7_unpad(const vector<uint8_t>& data, uint8_t block_size) {
	if (data.empty()) throw invalid_argument("Empty input cannot be unpadded");
	uint8_t pad_len = data.back();
	if (pad_len == 0 || pad_len > block_size || pad_len > data.size()) throw invalid_argument("Invalid PKCS#7 padding");
	for (size_t i = data.size() - pad_len; i < data.size(); ++i) {
		if (data[i] != pad_len) throw invalid_argument("Invalid PKCS#7 padding bytes");
	}
	return vector<uint8_t>(data.begin(), data.end() - pad_len);
}

}  // namespace des_sim
