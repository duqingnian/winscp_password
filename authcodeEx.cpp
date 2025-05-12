#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <chrono>
#include <random>
#include <thread>

using namespace std;
typedef unsigned char uchar;

#define PW_MAGIC  0xA3
#define PW_FLAG   0xFF

// ——— 原版不动 ———
int dec_next_char(string& s) {
    if (s.length() < 2) return 0;
    const string base = "0123456789ABCDEF";
    int a = base.find(s[0]);
    int b = base.find(s[1]);
    uchar r = (uchar)~(((a << 4) + b) ^ PW_MAGIC);
    s.erase(0, 2);
    return r;
}

string decrypt(string pwd, string key) {
    string clearpwd;
    uchar length, flag;

    flag = dec_next_char(pwd);

    if (flag == PW_FLAG) {
        dec_next_char(pwd);          // 跳过 “dummy” 字节
        length = dec_next_char(pwd); // 真正的数据长度
    }
    else {
        length = flag;
    }

    // 跳过 offset 个字符
    pwd.erase(0, (dec_next_char(pwd)) * 2);

    // 取出 length 个明文字节
    for (int i = 0; i < length; i++)
        clearpwd += (char)dec_next_char(pwd);

    // 校验并剥离 key
    if (flag == PW_FLAG) {
        if (clearpwd.substr(0, key.length()) != key)
            return "";               // 前缀不对就空
        clearpwd.erase(0, key.length());
    }
    return clearpwd;
}
// ———  end 原版 ———



// ——— 正确的 encrypt —— 完全对称上面的 decrypt —— 
string encrypt(const string& password, const string& key) {
    // 先把 key+password 拼在一起
    string full = key + password;
    string result;
    stringstream ss;

    // 1) 写入 enc_flag = ~(PW_FLAG ^ PW_MAGIC)
    {
        uchar enc_flag = (uchar)~((PW_FLAG) ^ PW_MAGIC);
        ss.str(""); ss.clear();
        ss << hex << uppercase << setw(2) << setfill('0') << (int)enc_flag;
        result += ss.str();
    }

    // 2) 写入 dummy=0 的加密
    {
        uchar enc_dummy = (uchar)~(0 ^ PW_MAGIC);
        ss.str(""); ss.clear();
        ss << hex << uppercase << setw(2) << setfill('0') << (int)enc_dummy;
        result += ss.str();
    }

    // 3) 写入 length 字段
    {
        uchar len = (uchar)full.length();
        uchar enc_len = (uchar)~(len ^ PW_MAGIC);
        ss.str(""); ss.clear();
        ss << hex << uppercase << setw(2) << setfill('0') << (int)enc_len;
        result += ss.str();
    }

    // 4) 写入 offset（我们固定 0）
    {
        uchar enc_off = (uchar)~(0 ^ PW_MAGIC);
        ss.str(""); ss.clear();
        ss << hex << uppercase << setw(2) << setfill('0') << (int)enc_off;
       result += ss.str();    }
        // 5) （offset=0，所以不补任何伪造字节）

    // 6) 写入 key+password 的每个字符
    for (unsigned char ch : full) {
        uchar enc_ch = (uchar)~(ch ^ PW_MAGIC);
        ss.str(""); ss.clear();
        ss << hex << uppercase << setw(2) << setfill('0') << (int)enc_ch;
        result += ss.str();
    }

    return result;
}
// ——— end encrypt ———


struct RandomOption {
    size_t length = 16;              // 长度
    bool useLowercase = true;        // 小写字母
    bool useUppercase = true;        // 大写字母
    bool useDigits = true;           // 数字
    bool useSymbols = false;         // 特殊字符
    std::string extraChars = "";     // 自定义字符（可选）
};
std::string generateRandom(const RandomOption& opt) {
    std::string charset;
    if (opt.useLowercase) charset += "abcdefghijklmnopqrstuvwxyz";
    if (opt.useUppercase) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (opt.useDigits)    charset += "0123456789";
    if (opt.useSymbols)   charset += "!@#$%^&*()-_=+[]{}|;:,.<>?";
    charset += opt.extraChars;

    if (charset.empty()) return "";

    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::mt19937 gen(static_cast<unsigned int>(seed));
    std::uniform_int_distribution<> dist(0, charset.size() - 1);

    std::string result;
    for (size_t i = 0; i < opt.length; ++i)
        result += charset[dist(gen)];

    return result;
}

// 格式化时间戳为 yyyy-MM-dd HH:mm:ss:SSS
string formatTimePoint(const chrono::system_clock::time_point& tp) {
    auto in_time_t = chrono::system_clock::to_time_t(tp);
    auto ms = chrono::duration_cast<chrono::milliseconds>(tp.time_since_epoch()) % 1000;

    std::tm bt;
#ifdef _WIN32
    localtime_s(&bt, &in_time_t);
#else
    localtime_r(&in_time_t, &bt);
#endif

    stringstream ss;
    ss << put_time(&bt, "%Y-%m-%d %H:%M:%S")
        << ":" << setfill('0') << setw(3) << ms.count();
    return ss.str();
}

// 格式化毫秒时长为 X秒Y毫秒
string formatDuration(int64_t ms) {
    int sec = static_cast<int>(ms / 1000);
    int ms_remain = static_cast<int>(ms % 1000);
    stringstream ss;
    ss << sec << "s" << ms_remain << "ms";
    return ss.str();
}

int main() {
    string user = "root";
    string host = "192.168.12.34";
    string key = user + host;

    RandomOption opt;
    opt.length = 64;
    opt.useLowercase = true;
    opt.useUppercase = true;
    opt.useDigits = true;
    opt.useSymbols = true;
    opt.extraChars = "#~-_";

    int matchCount = 0, mismatchCount = 0;

    auto startClock = chrono::steady_clock::now();
    auto startTime = chrono::system_clock::now();

    int loop_count = 100;

    for (int i = 1; i <= loop_count; ++i)
    {
        string password = generateRandom(opt);
        string crypted = encrypt(password, key);
        string plain = decrypt(crypted, key);
        bool match = (password == plain);

        if (match) matchCount++;
        else mismatchCount++;

        cout << "===== Test #" << i << " =====\n"
            << "Plain     : " << password << "\n"
            << "Encrypted : " << crypted << "\n"
            << "Decrypted : " << plain << "\n"
            << "Match     : " << (match ? "......Yes" : "......No") << "\n\n";

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    auto endClock = chrono::steady_clock::now();
    auto endTime = chrono::system_clock::now();
    auto durationMs = chrono::duration_cast<chrono::milliseconds>(endClock - startClock).count();

    cout << "================== Summary ==================\n";
    cout << "Total Tests   : "<< loop_count <<"\n";
    cout << "Match Count   : " << matchCount << "\n";
    cout << "Mismatch Count: " << mismatchCount << "\n";
    cout << "Start Time    : " << formatTimePoint(startTime) << "\n";
    cout << "End Time      : " << formatTimePoint(endTime) << "\n";
    cout << "Total Duration: " << formatDuration(durationMs) << "\n";


    return 0;
}