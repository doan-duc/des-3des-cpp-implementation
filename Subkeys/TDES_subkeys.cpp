#include "TDES_subkeys.hpp"
#include "DES_subkeys.hpp"

#include <chrono>
#include <iostream>

using namespace std;

namespace des_sim {
// Bọc hàm sinh khóa DES cơ bản cho đối tượng DESKey
vector<uint64_t> generate_subkeys_from_deskey(const DESKey& des_key, bool verbose) {
    return generate_subkeys(des_key.value, verbose);
}
// Sinh 3 tập khóa con (48 khóa) cho 3DES và đo thời gian thực thi
tuple<vector<uint64_t>, vector<uint64_t>, vector<uint64_t>, double> generate_all_3des_subkeys(
    const TripleDESKey& triple_key, bool verbose
) {
    const uint64_t k1 = triple_key.k1.value;
    const uint64_t k2 = triple_key.k2.value;
    const uint64_t k3 = triple_key.get_k3().value;

    if (verbose) {
        cout << "\n  === 3DES SUBKEY GENERATION ===\n";
        cout << "  K1: " << triple_key.k1.to_hex_str() << "\n";
        cout << "  K2: " << triple_key.k2.to_hex_str() << "\n";
        cout << "  K3: " << DESKey(k3).to_hex_str() << "\n";
    }

    auto start = chrono::high_resolution_clock::now();
    // Sinh khóa con độc lập cho K1, K2, K3
    auto sk1 = generate_subkeys(k1);
    auto sk2 = generate_subkeys(k2);
    auto sk3 = generate_subkeys(k3);
    auto end = chrono::high_resolution_clock::now();
    double elapsed_ms = chrono::duration<double, milli>(end - start).count();
    return {sk1, sk2, sk3, elapsed_ms};
}

}  // namespace des_sim
