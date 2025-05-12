#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define PW_MAGIC 0xA3
#define PW_FLAG  0xFF

#define MAX_LEN 256

// ===== 工具函数 =====
char* hex_char = "0123456789ABCDEF";

unsigned char hex_to_byte(char a, char b) {
    int high = strchr(hex_char, toupper(a)) - hex_char;
    int low  = strchr(hex_char, toupper(b)) - hex_char;
    return ~(unsigned char)(((high << 4) | low) ^ PW_MAGIC);
}

void byte_to_hex(unsigned char byte, char* out) {
    unsigned char enc = ~(byte ^ PW_MAGIC);
    out[0] = hex_char[(enc >> 4) & 0x0F];
    out[1] = hex_char[enc & 0x0F];
}

// ===== 加密函数 =====
void encrypt(const char* password, const char* key, char* out) {
    char full[MAX_LEN];
    snprintf(full, sizeof(full), "%s%s", key, password);
    size_t len = strlen(full);

    char* ptr = out;

    // FLAG
    byte_to_hex(PW_FLAG, ptr); ptr += 2;

    // dummy
    byte_to_hex(0, ptr); ptr += 2;

    // length
    byte_to_hex((unsigned char)len, ptr); ptr += 2;

    // offset
    byte_to_hex(0, ptr); ptr += 2;

    // payload
	size_t i = 0;
    for (i = 0; i < len; ++i) {
        byte_to_hex((unsigned char)full[i], ptr);
        ptr += 2;
    }
    *ptr = '\0';
}

// ===== 解密函数 =====
int decrypt(const char* input, const char* key, char* out) {
    const char* p = input;
    char result[MAX_LEN];
    size_t ri = 0;

    unsigned char flag = hex_to_byte(p[0], p[1]); p += 2;
    unsigned char length;

    if (flag == PW_FLAG) {
        p += 2; // dummy
        length = hex_to_byte(p[0], p[1]); p += 2;
    } else {
        length = flag;
    }

    unsigned char offset = hex_to_byte(p[0], p[1]); p += 2;
    p += offset * 2;
	int i = 0;
    for (i = 0; i < length; ++i) {
        result[ri++] = (char)hex_to_byte(p[0], p[1]);
        p += 2;
    }
    result[ri] = '\0';

    size_t key_len = strlen(key);
    if (flag == PW_FLAG) {
        if (strncmp(result, key, key_len) != 0) return 0;
        strcpy(out, result + key_len);
    } else {
        strcpy(out, result);
    }
    return 1;
}

// ===== 随机密码生成 =====
void generate_random(char* out, size_t len) {
    const char* charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?#~-_";
    size_t clen = strlen(charset);
	size_t i = 0;
    for (i = 0; i < len; ++i) {
        out[i] = charset[rand() % clen];
    }
    out[len] = '\0';
}

// ===== 时间格式 =====
void format_time(char* buf, size_t len) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d:%03ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
}

void format_duration(long ms, char* out) {
    sprintf(out, "%lds%ldms", ms / 1000, ms % 1000);
}

// ===== 主函数 =====
int main() {
    srand((unsigned int)time(NULL));

    const char* user = "root";
    const char* host = "192.168.12.34";
    char key[64];
    snprintf(key, sizeof(key), "%s%s", user, host);

    int loop_count = 100;
    int match = 0, mismatch = 0;

    char now[64], dur[32];
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    format_time(now, sizeof(now));
    printf("Start Time    : %s\n", now);
	int i = 1;
    for (i = 1; i <= loop_count; ++i) {
        char password[128], encrypted[512], decrypted[128];

        generate_random(password, 64);
        encrypt(password, key, encrypted);
        int success = decrypt(encrypted, key, decrypted);

        printf("===== Test #%d =====\n", i);
        printf("Plain     : %s\n", password);
        printf("Encrypted : %s\n", encrypted);
        printf("Decrypted : %s\n", success ? decrypted : "(fail)");
        printf("Match     : %s\n\n", (success && strcmp(password, decrypted) == 0) ? "......Yes" : "......No");

        if (success && strcmp(password, decrypted) == 0)
            match++;
        else
            mismatch++;

        struct timespec delay = {0, 100 * 1000000}; // 100ms
        nanosleep(&delay, NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
    format_time(now, sizeof(now));
    format_duration(elapsed_ms, dur);

    printf("End Time      : %s\n", now);
    printf("Total Duration: %s\n", dur);
    printf("Match Count   : %d\n", match);
    printf("Mismatch Count: %d\n", mismatch);

    return 0;
}
