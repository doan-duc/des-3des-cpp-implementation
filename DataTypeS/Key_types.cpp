#include "Key_types.hpp"

#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

using namespace std;

namespace des_sim {

static string sanitize_key_hex(const string& input) {
	string out;
	out.reserve(input.size());
	for (char c : input) {
		if (isxdigit(static_cast<unsigned char>(c))) out.push_back(static_cast<char>(toupper(static_cast<unsigned char>(c))));
	}
	return out;
}

DESKey DESKey::from_hex(const string& hex_str) {
	const string clean = sanitize_key_hex(hex_str);
	if (clean.size() != 16) throw invalid_argument("DES key must be exactly 16 hex characters");
	return DESKey(stoull(clean, nullptr, 16));
}

string DESKey::to_hex_str() const {
	ostringstream oss;
	oss << uppercase << hex << setw(16) << setfill('0') << value;
	return oss.str();
}

}  // namespace des_sim
