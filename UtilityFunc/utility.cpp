#include "utility.hpp"

#include <cctype>
#include <iomanip>
#include <iostream>
#include <exception>
#include <sstream>
#include <stdexcept>

using namespace std;

namespace des_sim {

const string BOLD = "\033[1m";
const string GREEN = "\033[92m";
const string CYAN = "\033[96m";
const string YELLOW = "\033[93m";
const string RED = "\033[91m";
const string RESET = "\033[0m";

void cprint(const string& text, const string& color) {
    cout << color << text << RESET << "\n";
}

string to_upper_ascii(string s) {
    for (char& c : s) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return s;
}

string read_choice(const string& prompt, const vector<string>& valid) {
    while (true) {
        cout << "\n" << BOLD << prompt << RESET;
        string choice;
        getline(cin, choice);
        for (const auto& v : valid) {
            if (choice == v) return choice;
        }
        cprint("  X Lua chon khong hop le!", RED);
    }
}

bool read_yes_no(const string& prompt) {
    while (true) {
        cout << prompt;
        string yn;
        getline(cin, yn);
        if (!yn.empty()) {
            char c = static_cast<char>(tolower(static_cast<unsigned char>(yn[0])));
            if (c == 'y') return true;
            if (c == 'n') return false;
        }
        cprint("  X Vui long nhap y hoac n.", RED);
    }
}

DESKey input_des_key(const string& label) {
    while (true) {
        cprint("  Nhap khoa " + label + " (16 ky tu hex):", BOLD);
        cout << "  > ";
        string hex;
        getline(cin, hex);
        try {
            return DESKey::from_hex(hex);
        } catch (const exception&) {
            cprint("  X Khoa khong hop le, can dung 16 ky tu hex.", RED);
        }
    }
}

TripleDESKey input_key_prompt(bool use_3des) {
    if (use_3des) {
        cprint("\n--- NHAP 3 KHOA CHO 3DES ---", BOLD);
        DESKey k1 = input_des_key("K1");
        DESKey k2 = input_des_key("K2");
        DESKey k3 = input_des_key("K3");
        return TripleDESKey(k1, k2, k3);
    }
    DESKey k = input_des_key("DES");
    return TripleDESKey(k, k);
}

string get_mode_choice() {
    cout << "\n  Chon che do ma hoa (Block Mode):\n";
    cout << "  1. ECB (Electronic Codebook)\n";
    cout << "  2. CBC (Cipher Block Chaining)\n";
    string c = read_choice("Lua chon: ", {"1", "2"});
    return c == "1" ? "ECB" : "CBC";
}

uint64_t get_iv_input() {
    while (true) {
        cprint("\n  Nhap Vector khoi tao IV (16 ky tu hex):", BOLD);
        cout << "  > ";
        string iv_hex;
        getline(cin, iv_hex);
        try {
            string clean = sanitize_hex(iv_hex);
            if (clean.size() != 16) throw invalid_argument("bad length");
            return stoull(clean, nullptr, 16);
        } catch (const exception&) {
            cprint("  X IV khong hop le, can dung 16 ky tu hex.", RED);
        }
    }
}

vector<uint8_t> read_encrypt_input(bool& ok) {
    cout << "\n  Ban muon nhap gi?\n";
    cout << "  1. Van ban (Text/String)\n";
    cout << "  2. Chuoi Hex\n";
    string choice = read_choice("Lua chon: ", {"1", "2"});
    if (choice == "2") {
        cout << "  Nhap chuoi Plaintext (Hex): ";
        string hex_input;
        getline(cin, hex_input);
        try {
            ok = true;
            return hex_to_bytes(hex_input);
        } catch (const exception&) {
            cprint("  X Chuoi Hex khong hop le!", RED);
            ok = false;
            return {};
        }
    }
    cout << "  Nhap van ban can ma hoa: ";
    string text;
    getline(cin, text);
    ok = true;
    return vector<uint8_t>(text.begin(), text.end());
}

bool is_valid_utf8(const vector<uint8_t>& data) {
    size_t i = 0;
    while (i < data.size()) {
        uint8_t c = data[i];
        if ((c & 0x80) == 0x00) {
            ++i;
            continue;
        }
        if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= data.size()) return false;
            if ((data[i + 1] & 0xC0) != 0x80) return false;
            if (c < 0xC2) return false;
            i += 2;
            continue;
        }
        if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= data.size()) return false;
            if ((data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80) return false;
            if (c == 0xE0 && data[i + 1] < 0xA0) return false;
            if (c == 0xED && data[i + 1] >= 0xA0) return false;
            i += 3;
            continue;
        }
        if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= data.size()) return false;
            if ((data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80 || (data[i + 3] & 0xC0) != 0x80) return false;
            if (c == 0xF0 && data[i + 1] < 0x90) return false;
            if (c > 0xF4 || (c == 0xF4 && data[i + 1] > 0x8F)) return false;
            i += 4;
            continue;
        }
        return false;
    }
    return true;
}


string bytes_to_hex(const vector<uint8_t>& data) {
    ostringstream oss;
    for (uint8_t b : data) oss << hex << setw(2) << setfill('0') << uppercase << static_cast<int>(b);
    return oss.str();
}

vector<uint8_t> hex_to_bytes(const string& hex) {
    const string clean = sanitize_hex(hex);
    if (clean.size() % 2 != 0) throw invalid_argument("Hex string length must be even");
    vector<uint8_t> out;
    out.reserve(clean.size() / 2);
    for (size_t i = 0; i < clean.size(); i += 2) out.push_back(static_cast<uint8_t>(stoi(clean.substr(i, 2), nullptr, 16)));
    return out;
}

string sanitize_hex(const string& input) {
    string out;
    out.reserve(input.size());
    for (char c : input) {
        if (isxdigit(static_cast<unsigned char>(c))) out.push_back(static_cast<char>(toupper(static_cast<unsigned char>(c))));
    }
    return out;
}

}  // namespace des_sim
