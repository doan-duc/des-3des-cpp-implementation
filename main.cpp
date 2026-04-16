#include "DataTypes/Block_types.hpp"
#include "DataTypes/Key_types.hpp"
#include "Subkeys/DES_subkeys.hpp"
#include "Subkeys/TDES_subkeys.hpp"
#include "DES/DES.hpp"
#include "XuLyHoanViVaSbox/IP_and_Sbox.hpp"
#include "ModeTDES/TDES.hpp"
#include "UtilityFunc/utility.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

// Gom cac file logic lai de trinh bien dich hieu duoc noi dung ham
#include "DataTypes/Block_types.cpp"
#include "DataTypes/Key_types.cpp"
#include "Subkeys/DES_subkeys.cpp"
#include "Subkeys/TDES_subkeys.cpp"
#include "DES/DES.cpp"
#include "ModeTDES/TDES.cpp"
#include "UtilityFunc/utility.cpp"

using namespace std;

int main() {
    using namespace des_sim;
    // Bat dau vong lap de chuong trinh chay lien tuc den khi minh muon thoat
    while (true) {
#ifdef _WIN32
        system("cls");
#else
        system("clear");
#endif

        // In cai tieu de cho dep mat
        cprint("============================================", CYAN);
        cprint("         HE THONG MO PHONG DES / 3DES       ", CYAN);
        cprint("============================================", CYAN);
        cout << "  1. Ma hoa van ban (Text -> Hex)\n";
        cout << "  2. Giai ma van ban (Hex -> Text)\n";
        cout << "  0. Thoat\n";
        string choice = read_choice("Lua chon cong viec: ", {"0", "1", "2"});
        if (choice == "0") return 0; // Neu chon 0 thi nghi choe, thoat luon

        // Hoi cac thong so can thiet: co dung 3DES ko, khoa la gi, chay kieu ECB hay CBC
        bool use_3des = read_yes_no("  Su dung 3DES? (y/n): ");
        TripleDESKey tkey = input_key_prompt(use_3des);
        string mode = get_mode_choice();
        
        // Neu dung che do CBC thi can them mot cai ma IV (vector khoi tao)
        uint64_t iv = 0;
        if (mode == "CBC") iv = get_iv_input();

        // Neu bam phim 1 thi vao luong ma hoa
        if (choice == "1") {
            cprint("\n>>> CHUC NANG: MA HOA VAN BAN", BOLD + CYAN);
            bool ok = false;
            vector<uint8_t> data = read_encrypt_input(ok); // Lay chu chuoi ban muon ma hoa
            
            if (ok) {
                // Kiem tra xem du lieu co chia het cho 8 byte ko, neu le thi phai them "dem" (padding)
                bool is_multiple = !data.empty() && (data.size() % 8 == 0);
                bool use_padding = !is_multiple; 

                // Thuc hien ma hoa thuc su o day
                pair<vector<uint8_t>, double> encrypt_result = encrypt_data(data, tkey, use_3des, use_padding, mode, iv);
                const vector<uint8_t>& ct = encrypt_result.first;

                // Show ket qua ra man hinh cho nguoi dung xem
                cprint("\n--- KET QUA MA HOA ---", GREEN);
                cout << "  Che do         : " << mode << "\n";
                if (mode == "CBC") cout << "  Vector IV      : " << to_upper_ascii(DESBlock(iv).to_hex_str()) << "\n";
                cout << "  Ciphertext (H) : " << bytes_to_hex(ct) << "\n";
                cout << "  Do dai         : " << ct.size() << " bytes (" << (ct.size() / 8) << " blocks)\n";
                
                // Bao cho nguoi dung biet la co phai "bu" them du lieu cho du block ko
                if (use_padding) {
                    cprint("  Status: [Smart Padding] Du lieu le -> Da dem PKCS#7.", YELLOW);
                } else {
                    cprint("  Status: [Smart Padding] Du lieu chuan 64-bit -> KHONG dem.", YELLOW);
                }
            }
        } 
        // Neu ko chon 1 (tuc la chon 2) thi vao luong giai ma
        else {
            cprint("\n>>> CHUC NANG: GIAI MA VAN BAN", BOLD + YELLOW);
            cout << "\n  Nhap chuoi Ciphertext (Hex): ";
            string hex;
            getline(cin, hex);

            try {
                // Chuyen cai chuoi Hex vua nhap thanh dang byte de may hieu
                vector<uint8_t> data = hex_to_bytes(hex);
                vector<uint8_t> pt;
                string mode_msg;

                try {
                    // Thu giai ma kieu co padding truoc, neu dung thi tot
                    auto out = decrypt_data(data, tkey, use_3des, true, mode, iv);
                    pt = move(out.first);
                    mode_msg = "Giai ma " + mode + " voi PKCS#7 Padding";
                } catch (const exception&) {
                    // Neu kieu tren loi thi giai ma kieu tho (raw), ko can padding
                    auto out = decrypt_data(data, tkey, use_3des, false, mode, iv);
                    pt = move(out.first);
                    mode_msg = "Giai ma " + mode + " KHONG Padding (Raw)";
                }

                // In ket qua ra, neu la chu doc duoc thi in ra chu, ko thi bao loi
                cprint("\n--- KET QUA GIAI MA ---", GREEN);
                cout << "  Che do xu ly   : " << mode_msg << "\n";
                if (mode == "CBC") cout << "  Vector IV      : " << to_upper_ascii(DESBlock(iv).to_hex_str()) << "\n";
                cout << "  Plaintext (Hex): " << bytes_to_hex(pt) << "\n";

                // Kiem tra xem mang byte nay co phai la chu binh thuong ko
                if (is_valid_utf8(pt)) {
                    cout << "  Plaintext (Text): " << string(pt.begin(), pt.end()) << "\n";
                } else {
                    cout << "  Plaintext (Text): [Khong the giai ma UTF-8]\n";
                }
            } catch (const exception& e) {
                // Co loi gi phat sinh (nhap sai hex, sai khoa...) thi bao o day
                cprint(string("  X Loi giai ma: ") + e.what(), RED);
            }
        }
        cout << "\n" << BOLD << "Nhan Enter de quay lai Menu..." << RESET;
        string pause;
        getline(cin, pause);
    }
}