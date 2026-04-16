// Include khai bao ham encrypt_file/decrypt_file.
#include "inout.hpp"
// Include API ma hoa/giai ma block duoc dung ben duoi.
#include "../ModeTDES/TDES.hpp"

// Dung ifstream/ofstream de doc ghi file nhi phan.
#include <fstream>
// Dung iterator de doc toan bo file vao vector mot cach gon.
#include <iterator>
// Dung vector<uint8_t> de luu du lieu nhi phan.
#include <vector>

// Rut gon cu phap std:: trong file implementation nay.
using namespace std;

// Dat implementation trong namespace chung cua du an.
namespace des_sim {

// Ham ma hoa noi dung file dau vao va ghi ket qua ra file dau ra.
map<string, double> encrypt_file(
    const string& input_path, const string& output_path, const TripleDESKey& key, bool use_3des
) {
    // Mo file input o che do nhi phan.
    ifstream in(input_path, ios::binary);
    // Doc toan bo byte tu file input vao vector du lieu.
    vector<uint8_t> data((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    // Goi ham ma hoa du lieu (dang su dung mode ECB, co padding).
    pair<vector<uint8_t>, double> encrypt_result = encrypt_data(data, key, use_3des, true, "ECB", 0);
    // Lay ciphertext sau khi ma hoa.
    const vector<uint8_t>& ct = encrypt_result.first;
    // Lay thoi gian ma hoa (ms).
    double t = encrypt_result.second;

    // Mo file output o che do nhi phan de ghi ciphertext.
    ofstream out(output_path, ios::binary);
    // Ghi toan bo ciphertext ra file dau ra.
    out.write(reinterpret_cast<const char*>(ct.data()), static_cast<streamsize>(ct.size()));

    // Tra ve thong ke tong hop cua qua trinh ma hoa file.
    return {
        // Kich thuoc du lieu goc truoc ma hoa (byte).
        {"original_size", static_cast<double>(data.size())},
        // Kich thuoc du lieu sau ma hoa (byte).
        {"encrypted_size", static_cast<double>(ct.size())},
        // So block 8-byte cua ciphertext.
        {"num_blocks", static_cast<double>(ct.size() / 8)},
        // Thoi gian ma hoa tinh theo mili giay.
        {"t_enc_ms", t},
        // Truong de du phong thong ke keygen (hien dang de 0.0).
        {"t_keygen_ms", 0.0}
    };
}

// Ham giai ma noi dung file dau vao va ghi plaintext ra file dau ra.
map<string, double> decrypt_file(
    const string& input_path, const string& output_path, const TripleDESKey& key, bool use_3des
) {
    // Mo file input (ciphertext) o che do nhi phan.
    ifstream in(input_path, ios::binary);
    // Doc toan bo byte tu file ciphertext vao vector du lieu.
    vector<uint8_t> data((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    // Goi ham giai ma du lieu (dang su dung mode ECB, co bo padding).
    pair<vector<uint8_t>, double> decrypt_result = decrypt_data(data, key, use_3des, true, "ECB", 0);
    // Lay plaintext sau khi giai ma.
    const vector<uint8_t>& pt = decrypt_result.first;
    // Lay thoi gian giai ma (ms).
    double t = decrypt_result.second;

    // Mo file output o che do nhi phan de ghi plaintext.
    ofstream out(output_path, ios::binary);
    // Ghi toan bo plaintext ra file dau ra.
    out.write(reinterpret_cast<const char*>(pt.data()), static_cast<streamsize>(pt.size()));

    // Tra ve thong ke tong hop cua qua trinh giai ma file.
    return {
        // Kich thuoc du lieu dau vao da ma hoa (byte).
        {"encrypted_size", static_cast<double>(data.size())},
        // Kich thuoc du lieu dau ra sau giai ma (byte).
        {"decrypted_size", static_cast<double>(pt.size())},
        // Thoi gian giai ma tinh theo mili giay.
        {"t_dec_ms", t}
    };
}

// Ket thuc namespace des_sim.
}  // namespace des_sim
