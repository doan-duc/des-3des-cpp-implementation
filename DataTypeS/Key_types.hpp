#pragma once

#include <cstdint>
#include <string>

using namespace std;

namespace des_sim {

struct DESKey {
    uint64_t value{0};
    explicit DESKey(uint64_t v = 0) : value(v) {}

    static DESKey from_hex(const string& hex_str);
    string to_hex_str() const;
};

struct TripleDESKey {
    DESKey k1;
    DESKey k2;
    DESKey k3;
    bool has_k3{false};

    TripleDESKey(const DESKey& a, const DESKey& b, const DESKey& c) : k1(a), k2(b), k3(c), has_k3(true) {}
    TripleDESKey(const DESKey& a, const DESKey& b) : k1(a), k2(b), k3(a), has_k3(false) {}
    DESKey get_k3() const { return has_k3 ? k3 : k1; }
};

}  // namespace des_sim