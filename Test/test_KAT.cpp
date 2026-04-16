#include "../ModeTDES/TDES.hpp"
#include "../UtilityFunc/utility.hpp"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "../DataTypes/Block_types.cpp"
#include "../DataTypes/Key_types.cpp"
#include "../Subkeys/DES_subkeys.cpp"
#include "../Subkeys/TDES_subkeys.cpp"
#include "../DES/DES.cpp"
#include "../ModeTDES/TDES.cpp"
#include "../UtilityFunc/utility.cpp"

using namespace std;
using namespace des_sim;

namespace {

struct KatRecord {
    string file;
    string section;
    int count{-1};
    map<string, string> kv;
};

struct CheckTask {
    bool encrypt{true};
    string mode;
    uint64_t iv{0};
    string input_hex;
    string expected_hex;
    string label;
};

struct FileStats {
    long long total{0};
    long long passed{0};
    long long failed{0};
};

static string trim(const string& s) {
    // Dat moc bat dau tai dau chuoi.
    size_t b = 0;
    // Tang b cho den khi gap ky tu khong phai khoang trang dau dong.
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    // Dat moc ket thuc tai cuoi chuoi.
    size_t e = s.size();
    // Giam e khi ky tu cuoi van la khoang trang de bo phan du o cuoi dong.
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    // Cat chuoi tu b den e de lay noi dung da bo khoang trang hai dau.
    return s.substr(b, e - b);
}

static bool starts_with(const string& s, const string& prefix) {
    // Kiem tra do dai va so sanh doan dau cua s voi prefix.
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static bool parse_assignment(const string& line, string& key, string& value) {
    // Tim vi tri dau '=' de tach key va value.
    size_t pos = line.find('=');
    // Neu khong co '=' thi dong nay khong phai cap gan hop le.
    if (pos == string::npos) return false;
    // Lay phan ben trai '=', bo khoang trang va dua ve chu hoa.
    key = to_upper_ascii(trim(line.substr(0, pos)));
    // Lay phan ben phai '=', bo khoang trang va dua ve chu hoa.
    value = to_upper_ascii(trim(line.substr(pos + 1)));
    // Chi chap nhan khi key khong rong.
    return !key.empty();
}

static bool get_first_present(const KatRecord& rec, const vector<string>& keys, string& out) {
    // Duyet lan luot theo thu tu uu tien cua danh sach key.
    for (const string& key : keys) {
        // Bo qua key rong de tranh tra cuu khong can thiet.
        if (key.empty()) continue;
        // Tim key trong map du lieu cua record.
        auto it = rec.kv.find(key);
        // Neu tim thay thi lay gia tri va ket thuc ngay.
        if (it != rec.kv.end()) {
            out = it->second;
            return true;
        }
    }
    // Khong co key nao trung trong danh sach uu tien.
    return false;
}

static uint64_t parse_hex64(const string& hex_value) {
    // Lam sach chuoi hex (bo ky tu la, dua ve chu hoa).
    const string clean = sanitize_hex(hex_value);
    // IV/DES block phai dung 8 byte => 16 ky tu hex.
    if (clean.size() != 16) throw invalid_argument("IV phai gom dung 16 ky tu hex");
    // Chuyen chuoi hex da hop le thanh so nguyen 64-bit.
    return stoull(clean, nullptr, 16);
}

static vector<KatRecord> parse_rsp_file(const string& path, const string& display_name) {
    // Mo file vector theo duong dan da truyen vao.
    ifstream in(path);
    // Bao loi ngay neu khong mo duoc file.
    if (!in) throw runtime_error("Khong mo duoc file vector: " + display_name);

    // Chua danh sach record sau khi parse.
    vector<KatRecord> records;
    // Luu section hien tai, vi du ENCRYPT/DECRYPT.
    string current_section;
    // Luu record dang duoc xay dung.
    KatRecord current;
    // Danh dau da bat dau mot record hop le hay chua.
    bool active = false;

    // Dong record dang mo vao danh sach va reset lai bo dem record hien tai.
    auto flush_current = [&]() {
        // Chi push neu dang co record hop le dang mo.
        if (active) records.push_back(current);
        // Tao moi record rong cho lan parse tiep theo.
        current = KatRecord{};
        // Tat trang thai active de cho COUNT moi mo lai record.
        active = false;
    };

    // Bien tam cho tung dong doc tu file.
    string line;
    // Doc file theo tung dong cho den het file.
    while (getline(in, line)) {
        // Bo khoang trang dau/cuoi de parser on dinh hon.
        const string t = trim(line);
        // Bo qua dong rong va dong comment bat dau bang '#'.
        if (t.empty() || t[0] == '#') continue;

        // Neu la dong section [ENCRYPT]/[DECRYPT] thi cap nhat ngu canh.
        if (t.front() == '[' && t.back() == ']') {
            // Ket thuc record cu truoc khi doi section.
            flush_current();
            // Lay ten section ben trong dau ngoac vuong va dua ve chu hoa.
            current_section = to_upper_ascii(trim(t.substr(1, t.size() - 2)));
            continue;
        }

        // Khai bao key/value de tach dong KEY = VALUE.
        string key;
        string value;
        // Neu dong khong phai assignment hop le thi bo qua.
        if (!parse_assignment(t, key, value)) continue;

        // COUNT danh dau bat dau mot record moi.
        if (key == "COUNT") {
            // Dong record truoc (neu co) truoc khi mo record moi.
            flush_current();
            // Bat dau record moi.
            active = true;
            // Ghi ten file nguon cua record de phuc vu debug/thong ke.
            current.file = display_name;
            // Ghi section hien tai vao record.
            current.section = current_section;
            // Chuyen gia tri COUNT sang so nguyen.
            current.count = stoi(value);
            // Luu COUNT vao map kv de giu day du du lieu goc.
            current.kv[key] = value;
            continue;
        }

        // Neu chua co record active thi assignment hien tai khong thuoc record nao.
        if (!active) continue;
        // Ghi cap key/value vao record dang active.
        current.kv[key] = value;
    }

    // Dong record cuoi cung khi da doc het file.
    flush_current();
    // Tra ve toan bo record da parse.
    return records;
}

static pair<TripleDESKey, bool> parse_key_bundle(const KatRecord& rec) {
    // Bien tam chua gia tri khoa o dang gop (KEYS/KEY).
    string key_blob;
    // Thu lay truoc theo KEYS, sau do fallback sang KEY.
    if (get_first_present(rec, {"KEYS", "KEY"}, key_blob)) {
        // Lam sach chuoi hex khoa truoc khi tach.
        const string clean = sanitize_hex(key_blob);
        // 16 hex => mot khoa DES, map thanh TripleDESKey(k, k) va danh dau khong phai 3DES day du.
        if (clean.size() == 16) {
            DESKey k = DESKey::from_hex(clean);
            return {TripleDESKey(k, k), false};
        }
        // 32 hex => 2-key TDES.
        if (clean.size() == 32) {
            DESKey k1 = DESKey::from_hex(clean.substr(0, 16));
            DESKey k2 = DESKey::from_hex(clean.substr(16, 16));
            return {TripleDESKey(k1, k2), true};
        }
        // 48 hex => 3-key TDES.
        if (clean.size() == 48) {
            DESKey k1 = DESKey::from_hex(clean.substr(0, 16));
            DESKey k2 = DESKey::from_hex(clean.substr(16, 16));
            DESKey k3 = DESKey::from_hex(clean.substr(32, 16));
            return {TripleDESKey(k1, k2, k3), true};
        }
        // Cac do dai khac khong hop le voi DES/TDES.
        throw invalid_argument("Do dai KEYS khong ho tro tai COUNT=" + to_string(rec.count));
    }

    // Cac bien tam cho format tach rieng KEY1/KEY2/KEY3.
    string k1s;
    string k2s;
    string k3s;
    // Thu doc tung truong khoa rieng neu co.
    bool has_k1 = get_first_present(rec, {"KEY1"}, k1s);
    bool has_k2 = get_first_present(rec, {"KEY2"}, k2s);
    bool has_k3 = get_first_present(rec, {"KEY3"}, k3s);
    // Neu du 3 khoa thi dung che do 3-key TDES.
    if (has_k1 && has_k2 && has_k3) return {TripleDESKey(DESKey::from_hex(k1s), DESKey::from_hex(k2s), DESKey::from_hex(k3s)), true};
    // Neu co 2 khoa thi dung che do 2-key TDES.
    if (has_k1 && has_k2) return {TripleDESKey(DESKey::from_hex(k1s), DESKey::from_hex(k2s)), true};
    // Khong du du lieu khoa thi bao loi.
    throw invalid_argument("Thieu truong KEYS/KEY tai COUNT=" + to_string(rec.count));
}

static vector<CheckTask> build_tasks(const KatRecord& rec, const string& filename) {
    // Xac dinh record dang thuoc section ma hoa hay giai ma.
    const bool is_encrypt = rec.section == "ENCRYPT";
    const bool is_decrypt = rec.section == "DECRYPT";
    // Chi xu ly 2 section hop le, section khac bo qua.
    if (!is_encrypt && !is_decrypt) return {};

    // Nhan dien file nhom CBCI thong qua tien to ten file.
    const bool is_cbci = starts_with(filename, "TCBCI");
    // Nhan dien file nhom CBC (khong phai CBCI).
    const bool is_cbc = !is_cbci && starts_with(filename, "TCBC");

    // Chua danh sach task duoc tao tu record hien tai.
    vector<CheckTask> tasks;
    // Nhanh xu ly cho ECB/CBC thuong (moi COUNT chi tao 1 task).
    if (!is_cbci) {
        // Chon mode CBC neu file CBC, nguoc lai la ECB.
        const string mode = is_cbc ? "CBC" : "ECB";
        // IV mac dinh = 0, chi co y nghia khi mode CBC.
        uint64_t iv = 0;
        // Neu la CBC thi bat buoc doc IV tu record.
        if (is_cbc) {
            string iv_hex;
            if (!get_first_present(rec, {"IV"}, iv_hex)) return {};
            iv = parse_hex64(iv_hex);
        }

        // Bien tam cho input va expected cua task.
        string input_hex;
        string expected_hex;
        // Section ENCRYPT: input la plaintext, expected la ciphertext.
        if (is_encrypt) {
            if (!get_first_present(rec, {"PLAINTEXT"}, input_hex)) return {};
            if (!get_first_present(rec, {"CIPHERTEXT"}, expected_hex)) return {};
        } else {
            // Section DECRYPT: input la ciphertext, expected la plaintext.
            if (!get_first_present(rec, {"CIPHERTEXT"}, input_hex)) return {};
            if (!get_first_present(rec, {"PLAINTEXT"}, expected_hex)) return {};
        }

        // Tao 1 task duy nhat cho record ECB/CBC thuong.
        tasks.push_back(CheckTask{is_encrypt, mode, iv, input_hex, expected_hex, ""});
        return tasks;
    }

    // Nhanh xu ly CBCI: moi COUNT co the co 3 bo IV/input/expected.
    for (int ch = 1; ch <= 3; ++ch) {
        // Tao hau to chi so kenh: 1, 2, 3.
        const string n = to_string(ch);
        // Lay IV theo kenh, fallback ve IV chung neu can.
        string iv_hex;
        if (!get_first_present(rec, {"IV" + n, "IV"}, iv_hex)) continue;

        // Bien tam cho input/expected cua kenh hien tai.
        string input_hex;
        string expected_hex;
        // Danh dau co du thong tin input/expected hay chua.
        bool has_input = false;
        bool has_expected = false;

        // Nhanh mapping truong cho section ENCRYPT.
        if (is_encrypt) {
            has_input = get_first_present(rec, {"PLAINTEXT" + n, "PLAINTEXT"}, input_hex);
            if (ch == 1) {
                // Kenh 1 co the duoc dat ten CIPHERTEXT1 hoac CIPHERTEXT.
                has_expected = get_first_present(rec, {"CIPHERTEXT1", "CIPHERTEXT"}, expected_hex);
            } else {
                // Kenh 2/3 su dung truong CIPHERTEXT2/CIPHERTEXT3.
                has_expected = get_first_present(rec, {"CIPHERTEXT" + n}, expected_hex);
            }
        } else {
            // Nhanh mapping truong cho section DECRYPT.
            if (ch == 1) {
                // Kenh 1 uu tien CIPHERTEXT1 va PLAINTEXT1, co fallback ve ten chung.
                has_input = get_first_present(rec, {"CIPHERTEXT1", "CIPHERTEXT"}, input_hex);
                has_expected = get_first_present(rec, {"PLAINTEXT1", "PLAINTEXT"}, expected_hex);
            } else {
                // Kenh 2/3 lay input theo CIPHERTEXT2/3, expected theo PLAINTEXT2/3.
                has_input = get_first_present(rec, {"CIPHERTEXT" + n, "CIPHERTEXT1"}, input_hex);
                has_expected = get_first_present(rec, {"PLAINTEXT" + n}, expected_hex);
            }
        }

        // Neu kenh hien tai thieu input hoac expected thi bo qua kenh do.
        if (!has_input || !has_expected) continue;
        // Tao task CBC cho kenh hien tai, gan nhan [IV1]/[IV2]/[IV3] de debug.
        tasks.push_back(CheckTask{is_encrypt, "CBC", parse_hex64(iv_hex), input_hex, expected_hex, "[IV" + n + "]"});
    }

    // Tra ve toan bo task tao duoc tu record CBCI.
    return tasks;
}

static string resolve_kat_base(const vector<string>& files) {
    // Danh sach duong dan tuong doi se duoc thu lan luot.
    const vector<string> bases = {"KAT_TDES", "./KAT_TDES", "../KAT_TDES", "../../KAT_TDES", "../../../KAT_TDES"};
    // Thu tung base path den khi tim duoc file vector dau tien ton tai.
    for (const string& base : bases) {
        // Thu mo file dau tien trong danh sach de xac thuc base path.
        ifstream probe(base + "/" + files.front());
        // Neu mo duoc thi base path nay hop le.
        if (probe.good()) return base;
    }
    // Neu thu het ma van khong thay thi bao loi cau hinh duong dan.
    throw runtime_error("Khong tim thay thu muc KAT_TDES bang duong dan tuong doi");
}

}  // namespace

int main() {
    // Gom toan bo khoi xu ly chinh vao try de bat loi tap trung.
    try {
        // Danh sach day du cac file vector KAT can chay.
        const vector<string> kat_files = {
            "TECBvarkey.rsp",
            "TECBvartext.rsp",
            "TECBsubtab.rsp",
            "TECBpermop.rsp",
            "TECBinvperm.rsp",
            "TCBCvarkey.rsp",
            "TCBCvartext.rsp",
            "TCBCsubtab.rsp",
            "TCBCpermop.rsp",
            "TCBCinvperm.rsp",
            "TCBCIvarkey.rsp",
            "TCBCIvartext.rsp",
            "TCBCIsubtab.rsp",
            "TCBCIpermop.rsp",
            "TCBCIinvperm.rsp"
        };

        // Tim thu muc KAT_TDES theo cac duong dan tuong doi da cau hinh.
        const string kat_base = resolve_kat_base(kat_files);
        // In ra duong dan da duoc chon de de kiem tra moi truong chay.
        cout << "Duong dan KAT (tuong doi): " << kat_base << "\n";

        // Thong ke ket qua theo tung file .rsp.
        map<string, FileStats> by_file;
        // Dem tong so case da xu ly.
        long long total = 0;
        // Dem tong so case dat.
        long long passed = 0;
        // Dem tong so case truot.
        long long failed = 0;
        // Luu mot so loi dau tien de debug nhanh.
        vector<string> sample_failures;

        // Duyet lan luot tung file vector trong danh sach.
        for (const string& file : kat_files) {
            // Ghep duong dan day du theo base da tim duoc.
            const string path = kat_base + "/" + file;
            // Parse file thanh danh sach record KAT.
            vector<KatRecord> records = parse_rsp_file(path, file);

            // Duyet tung record trong file hien tai.
            for (const KatRecord& rec : records) {
                // Chi xu ly 2 section hop le, section khac bo qua.
                if (rec.section != "ENCRYPT" && rec.section != "DECRYPT") continue;

                // Chua cac task sinh ra tu record (co the 1 hoac nhieu task).
                vector<CheckTask> tasks;
                try {
                    // Sinh task tu record theo mode/section.
                    tasks = build_tasks(rec, file);
                } catch (const exception& e) {
                    // Dem case loi ngay tai buoc sinh task.
                    ++total;
                    ++failed;
                    ++by_file[file].total;
                    ++by_file[file].failed;
                    // Chi luu toi da 20 loi mau de output khong qua dai.
                    if (sample_failures.size() < 20) {
                        sample_failures.push_back(file + " COUNT=" + to_string(rec.count) + " " + rec.section + " loi tao task: " + e.what());
                    }
                    // Bo qua record nay va tiep tuc record ke tiep.
                    continue;
                }

                // Neu record khong tao duoc task hop le thi tinh la fail.
                if (tasks.empty()) {
                    ++total;
                    ++failed;
                    ++by_file[file].total;
                    ++by_file[file].failed;
                    // Luu loi mo ta ngan gon de truy vet record loi.
                    if (sample_failures.size() < 20) {
                        sample_failures.push_back(file + " COUNT=" + to_string(rec.count) + " " + rec.section + " khong tao duoc test task");
                    }
                    continue;
                }

                // Duyet tung task cu the duoc tao tu record.
                for (const CheckTask& task : tasks) {
                    // Moi task deu tang tong case.
                    ++total;
                    ++by_file[file].total;

                    try {
                        // Suy dien bo khoa va co/chua co 3DES tu record.
                        auto key_bundle = parse_key_bundle(rec);
                        // Tham chieu bo khoa da parse.
                        const TripleDESKey& key = key_bundle.first;
                        // Co dung TDES hay khong (false = DES/1-key map).
                        const bool use_3des = key_bundle.second;

                        // Chuyen input hex sang bytes truoc khi ma hoa/giai ma.
                        const vector<uint8_t> input = hex_to_bytes(task.input_hex);
                        // Vung chua ket qua dau ra sau khi chay ham ma hoa/giai ma.
                        vector<uint8_t> out;
                        // Chon duong di ma hoa hoac giai ma theo task.
                        if (task.encrypt) {
                            out = encrypt_data(input, key, use_3des, false, task.mode, task.iv).first;
                        } else {
                            out = decrypt_data(input, key, use_3des, false, task.mode, task.iv).first;
                        }

                        // Chuan hoa ket qua thuc te ve chuoi hex chu hoa.
                        const string actual = to_upper_ascii(bytes_to_hex(out));
                        // Chuan hoa ket qua mong doi ve chuoi hex chu hoa.
                        const string expected = to_upper_ascii(sanitize_hex(task.expected_hex));
                        // So sanh ket qua thuc te voi mong doi.
                        if (actual == expected) {
                            // Trung khop thi tinh la pass.
                            ++passed;
                            ++by_file[file].passed;
                        } else {
                            // Sai khop thi tinh la fail.
                            ++failed;
                            ++by_file[file].failed;
                            // Luu toi da 20 loi dau tien de de xem nhanh.
                            if (sample_failures.size() < 20) {
                                sample_failures.push_back(
                                    file + " COUNT=" + to_string(rec.count) + " " + rec.section + task.label +
                                    " mong doi=" + expected + " thuc te=" + actual
                                );
                            }
                        }
                    } catch (const exception& e) {
                        // Neu co exception trong khi chay task thi danh dau fail.
                        ++failed;
                        ++by_file[file].failed;
                        // Luu thong tin loi de debug nhanh.
                        if (sample_failures.size() < 20) {
                            sample_failures.push_back(file + " COUNT=" + to_string(rec.count) + " " + rec.section + task.label + " loi khi chay: " + e.what());
                        }
                    }
                }
            }
        }

        // In tong ket chung sau khi chay xong tat ca file.
        cout << "\n===== TONG KET KAT =====\n";
        cout << "Tong so : " << total << "\n";
        cout << "Dat     : " << passed << "\n";
        cout << "Truot   : " << failed << "\n";

        // In thong ke chi tiet theo tung file vector.
        cout << "\n===== THEO TUNG FILE =====\n";
        // Duyet map thong ke de in tung dong ket qua.
        for (const auto& kv : by_file) {
            const string& file = kv.first;
            const FileStats& st = kv.second;
            cout << file << " -> tong=" << st.total << ", dat=" << st.passed << ", truot=" << st.failed << "\n";
        }

        // Neu co loi thi in danh sach loi mau da thu thap.
        if (!sample_failures.empty()) {
            cout << "\n===== CAC LOI DAU TIEN =====\n";
            for (const string& msg : sample_failures) cout << msg << "\n";
        }

        // Khong co loi => tra ma 0.
        return failed == 0 ? 0 : 1;
    } catch (const exception& e) {
        // Bat loi nghiem trong ngoai du kien va tra ma 2.
        cerr << "Loi nghiem trong khi chay KAT: " << e.what() << "\n";
        return 2;
    }
}
