import random
import string
import time
from datetime import datetime

PW_MAGIC = 0xA3
PW_FLAG = 0xFF

def dec_next_char(s):
    if len(s) < 2:
        return 0, s
    base = "0123456789ABCDEF"
    a = base.find(s[0])
    b = base.find(s[1])
    r = ~((a << 4) + b ^ PW_MAGIC) & 0xFF
    return r, s[2:]

def decrypt(pwd, key):
    clearpwd = ""
    flag, pwd = dec_next_char(pwd)

    if flag == PW_FLAG:
        _, pwd = dec_next_char(pwd)          # dummy byte
        length, pwd = dec_next_char(pwd)
    else:
        length = flag

    offset, pwd = dec_next_char(pwd)
    pwd = pwd[offset * 2:]

    for _ in range(length):
        ch, pwd = dec_next_char(pwd)
        clearpwd += chr(ch)

    if flag == PW_FLAG:
        if not clearpwd.startswith(key):
            return ""
        clearpwd = clearpwd[len(key):]
    return clearpwd

def encrypt(password, key):
    full = key + password
    result = ""

    def enc_byte(b):
        return "{:02X}".format(~(b ^ PW_MAGIC) & 0xFF)

    result += enc_byte(PW_FLAG)
    result += enc_byte(0)  # dummy
    result += enc_byte(len(full))
    result += enc_byte(0)  # offset = 0

    for ch in full:
        result += enc_byte(ord(ch))

    return result

def generate_random(opt):
    charset = ''
    if opt['useLowercase']: charset += string.ascii_lowercase
    if opt['useUppercase']: charset += string.ascii_uppercase
    if opt['useDigits']: charset += string.digits
    if opt['useSymbols']: charset += '!@#$%^&*()-_=+[]{}|;:,.<>?'
    charset += opt['extraChars']
    return ''.join(random.choice(charset) for _ in range(opt['length']))

def format_time(ts):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S:%f')[:-3]

def format_duration(ms):
    return f"{ms // 1000}s{ms % 1000}ms"

# === Main Logic ===
if __name__ == '__main__':
    user = "root"
    host = "192.168.12.34"
    key = user + host

    opt = {
        'length': 64,
        'useLowercase': True,
        'useUppercase': True,
        'useDigits': True,
        'useSymbols': True,
        'extraChars': '#~-_'
    }

    match_count = 0
    mismatch_count = 0
    loop_count = 100

    start_time = time.time()
    print("Start Time    :", format_time(start_time))

    for i in range(1, loop_count + 1):
        password = generate_random(opt)
        crypted = encrypt(password, key)
        plain = decrypt(crypted, key)
        match = (password == plain)
        if match:
            match_count += 1
        else:
            mismatch_count += 1

        print(f"===== Test #{i} =====")
        print("Plain     :", password)
        print("Encrypted :", crypted)
        print("Decrypted :", plain)
        print("Match     :", "......Yes" if match else "......No\n")
        time.sleep(0.1)

    end_time = time.time()
    print("=============================================")
    print("End Time      :", format_time(end_time))
    print("Total Duration:", format_duration(int((end_time - start_time) * 1000)))
    print("Match Count   :", match_count)
    print("Mismatch Count:", mismatch_count)
