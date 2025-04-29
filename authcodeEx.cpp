#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>

using namespace std;
typedef unsigned char uchar;

#define PW_MAGIC  0xA3
#define PW_FLAG   0xFF

// ������ ԭ�治�� ������
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
        dec_next_char(pwd);          // ���� ��dummy�� �ֽ�
        length = dec_next_char(pwd); // ���������ݳ���
    }
    else {
        length = flag;
    }

    // ���� offset ���ַ�
    pwd.erase(0, (dec_next_char(pwd)) * 2);

    // ȡ�� length �������ֽ�
    for (int i = 0; i < length; i++)
        clearpwd += (char)dec_next_char(pwd);

    // У�鲢���� key
    if (flag == PW_FLAG) {
        if (clearpwd.substr(0, key.length()) != key)
            return "";               // ǰ׺���ԾͿ�
        clearpwd.erase(0, key.length());
    }
    return clearpwd;
}
// ������  end ԭ�� ������



// ������ ��ȷ�� encrypt ���� ��ȫ�Գ������ decrypt ���� 
string encrypt(const string& password, const string& key) {
    // �Ȱ� key+password ƴ��һ��
    string full = key + password;
    string result;
    stringstream ss;

    // 1) д�� enc_flag = ~(PW_FLAG ^ PW_MAGIC)
    {
        uchar enc_flag = (uchar)~((PW_FLAG) ^ PW_MAGIC);
        ss.str(""); ss.clear();
        ss << hex << uppercase << setw(2) << setfill('0') << (int)enc_flag;
        result += ss.str();
    }

    // 2) д�� dummy=0 �ļ���
    {
        uchar enc_dummy = (uchar)~(0 ^ PW_MAGIC);
        ss.str(""); ss.clear();
        ss << hex << uppercase << setw(2) << setfill('0') << (int)enc_dummy;
        result += ss.str();
    }

    // 3) д�� length �ֶ�
    {
        uchar len = (uchar)full.length();
        uchar enc_len = (uchar)~(len ^ PW_MAGIC);
        ss.str(""); ss.clear();
        ss << hex << uppercase << setw(2) << setfill('0') << (int)enc_len;
        result += ss.str();
    }

    // 4) д�� offset�����ǹ̶� 0��
    {
        uchar enc_off = (uchar)~(0 ^ PW_MAGIC);
        ss.str(""); ss.clear();
        ss << hex << uppercase << setw(2) << setfill('0') << (int)enc_off;
       result += ss.str();    }
        // 5) ��offset=0�����Բ����κ�α���ֽڣ�

    // 6) д�� key+password ��ÿ���ַ�
    for (unsigned char ch : full) {
        uchar enc_ch = (uchar)~(ch ^ PW_MAGIC);
        ss.str(""); ss.clear();
        ss << hex << uppercase << setw(2) << setfill('0') << (int)enc_ch;
        result += ss.str();
    }

    return result;
}
// ������ end encrypt ������



int main() {
    string user = "root";
    string host = "192.168.12.34";
    string key = user + host;

    string password = "my_test_password_123_$#@";
    string crypted = encrypt(password, key);
    string plain = decrypt(crypted, key);

    cout << "Plain   : " << password << "\n"
        << "Crypted : " << crypted << "\n"
        << "Decrypted: " << plain << endl;
    return 0;
}
