// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <x86intrin.h>

#define ZEROMANI_MAGIC      0x494E414D4F52455AULL
#define MAX_CAPSULE_PAYLOAD (64ULL * 1024ULL * 1024ULL) /* Жёсткий потолок размера капсулы 64 МБ против OOM DoS */

/* [МЕТКА 1: Заголовок зашифрованной капсулы ядра (40 байт)] */
typedef struct __attribute__((packed)) {
    uint64_t magic;       /* Авторская подпись "ZEROMANI" */
    uint64_t version;     /* Версия формата капсулы (1) */
    uint64_t payload_len; /* Точный размер зашифрованного бинарного ядра в байтах */
    uint64_t nonce;       /* Одноразовая аппаратная соль (RDTSC + /dev/urandom) */
    uint64_t mac;         /* Контрольный код целостности MAC */
} capsule_hdr_t;

static inline uint64_t rotl64(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

/* [МЕТКА 2: Мутагенный потоковый шифратор ARX с нелинейной перестройкой состояния] */
static void mutagen_xor_stream(uint8_t *buf, size_t len, const uint64_t *key, uint64_t nonce) {
    if (!buf || !key || len == 0) return;
    uint64_t s0 = *(key + 0) ^ nonce;
    uint64_t s1 = *(key + 1) ^ rotl64(nonce, 17);
    uint64_t s2 = *(key + 2) ^ rotl64(nonce, 33);
    uint64_t s3 = *(key + 3) ^ 0x9E3779B97F4A7C15ULL;

    size_t i = 0;
    while (i + 8 <= len) {
        s0 += s1; s1 = rotl64(s1, 13) ^ s0;
        s2 += s3; s3 = rotl64(s3, 29) ^ s2;
        uint64_t gamma = (s0 ^ s2) + rotl64(s1 ^ s3, 21);
        s0 ^= rotl64(gamma, 7);

        uint64_t word = 0;
        memcpy(&word, buf + i, 8);
        word ^= gamma;
        memcpy(buf + i, &word, 8);
        i += 8;
    }
    if (i < len) {
        s0 += s1; s1 = rotl64(s1, 13) ^ s0;
        s2 += s3; s3 = rotl64(s3, 29) ^ s2;
        uint64_t gamma = (s0 ^ s2) + rotl64(s1 ^ s3, 21);
        uint8_t *gbytes = (uint8_t *)&gamma;
        for (size_t r = 0; i + r < len; r++) {
            *(buf + i + r) ^= *(gbytes + r);
        }
    }
}

/* [МЕТКА 3: Вычисление контрольного кода целостности MAC по ключу эпохи и соли] */
static uint64_t compute_mac(const uint8_t *buf, size_t len, const uint64_t *key, uint64_t nonce) {
    uint64_t h = 0xCBF29CE484222325ULL ^ nonce ^ *(key + 0) ^ *(key + 3);
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)(*(buf + i));
        h *= 0x100000001B3ULL;
        h = rotl64(h, 5);
    }
    return h;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Использование: %s <enc|verify> <входной_файл> <капсула> <файл_ключа>\n", *(argv + 0));
        return 1;
    }
    char mode = **(argv + 1);
    const char *in_path = *(argv + 2);
    const char *cap_path = *(argv + 3);
    const char *key_path = *(argv + 4);

    /* [МЕТКА 4: Режим упаковки и шифрования ядра в подписанную капсулу (enc)] */
    if (mode == 'e') {
        FILE *fi = fopen(in_path, "rb");
        if (!fi) { perror("fopen input"); return 1; }
        if (fseek(fi, 0, SEEK_END) != 0) { fclose(fi); return 1; }
        long fsz = ftell(fi);
        if (fsz <= 0 || (uint64_t)fsz > MAX_CAPSULE_PAYLOAD || fseek(fi, 0, SEEK_SET) != 0) {
            fclose(fi); return 1;
        }

        size_t len = (size_t)fsz;
        uint8_t *data = malloc(len);
        if (!data) { fclose(fi); return 1; }
        if (fread(data, 1, len, fi) != len) {
            explicit_bzero(data, len); free(data); fclose(fi); return 1;
        }
        fclose(fi);

        /* [МЕТКА 5: Генерация 256-битного ключа и соли из /dev/urandom + RDTSC] */
        uint64_t *key = calloc(4, sizeof(uint64_t));
        if (!key) { explicit_bzero(data, len); free(data); return 1; }
        int ur = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (ur < 0 || read(ur, key, 32) != 32) {
            if (ur >= 0) close(ur);
            explicit_bzero(key, 32); free(key);
            explicit_bzero(data, len); free(data);
            return 1;
        }
        uint64_t nonce = __rdtsc();
        uint64_t extra = 0;
        if (read(ur, &extra, 8) == 8) nonce ^= extra;
        close(ur);

        uint64_t mac = compute_mac(data, len, key, nonce);
        mutagen_xor_stream(data, len, key, nonce);

        capsule_hdr_t hdr = {
            .magic = ZEROMANI_MAGIC,
            .version = 1,
            .payload_len = len,
            .nonce = nonce,
            .mac = mac
        };

        FILE *fc = fopen(cap_path, "wb");
        if (!fc) {
            explicit_bzero(key, 32); free(key);
            explicit_bzero(data, len); free(data);
            return 1;
        }
        int w_ok = (fwrite(&hdr, sizeof(hdr), 1, fc) == 1 && fwrite(data, 1, len, fc) == len);
        fclose(fc);

        /* [МЕТКА 6: Сохранение 256-битного ключа со строгими правами 0600 и затирание RAM (explicit_bzero)] */
        int kfd = open(key_path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (!w_ok || kfd < 0 || write(kfd, key, 32) != 32) {
            if (kfd >= 0) close(kfd);
            explicit_bzero(key, 32); free(key);
            explicit_bzero(data, len); free(data);
            return 1;
        }
        close(kfd);

        explicit_bzero(data, len); free(data);
        explicit_bzero(key, 32); free(key);

        printf("[МУТАГЕН-ШИФРАТОР] Ядро упаковано в %s (%zu байт) + 256-бит ключ %s\n",
               cap_path, len + sizeof(hdr), key_path);
        return 0;
    }

    /* [МЕТКА 7: Режим верификации и расшифровки капсулы в RAM с контролем MAC (verify)] */
    if (mode == 'v') {
        uint64_t *key = calloc(4, sizeof(uint64_t));
        if (!key) return 1;
        FILE *fk = fopen(key_path, "rb");
        if (!fk) { free(key); return 1; }
        if (fread(key, 1, 32, fk) != 32) {
            explicit_bzero(key, 32); free(key); fclose(fk); return 1;
        }
        fclose(fk);

        FILE *fc = fopen(cap_path, "rb");
        if (!fc) { explicit_bzero(key, 32); free(key); return 1; }
        capsule_hdr_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, fc) != 1 || hdr.magic != ZEROMANI_MAGIC ||
            hdr.payload_len == 0 || hdr.payload_len > MAX_CAPSULE_PAYLOAD) {
            fprintf(stderr, "Ошибка: неверная авторская метка или размер капсулы!\n");
            explicit_bzero(key, 32); free(key); fclose(fc);
            return 1;
        }

        size_t plen = (size_t)hdr.payload_len;
        uint8_t *data = malloc(plen);
        if (!data) { explicit_bzero(key, 32); free(key); fclose(fc); return 1; }
        if (fread(data, 1, plen, fc) != plen) {
            explicit_bzero(data, plen); free(data);
            explicit_bzero(key, 32); free(key); fclose(fc);
            return 1;
        }
        fclose(fc);

        mutagen_xor_stream(data, plen, key, hdr.nonce);
        uint64_t check_mac = compute_mac(data, plen, key, hdr.nonce);
        uint64_t diff = check_mac ^ hdr.mac;
        __asm__ __volatile__("" : "+r"(diff) :: "memory");

        /* При любом несовпадении MAC немедленно выжигаем расшифрованные байты в RAM */
        explicit_bzero(data, plen); free(data);
        explicit_bzero(key, 32); free(key);

        if (diff != 0ULL) {
            fprintf(stderr, "ТРЕВОГА: нарушена целостность ядра (MAC mismatch)!\n");
            return 1;
        }

        printf("[ПРОВЕРКА КАПСУЛЫ] Метка: %.8s | Расшифровано в RAM: %llu байт | Целостность MAC: ОК (0x%016llx)\n",
               (char *)&hdr.magic, (unsigned long long)hdr.payload_len, (unsigned long long)check_mac);
        return 0;
    }

    fprintf(stderr, "Ошибка: неизвестный режим '%c'\n", mode);
    return 1;
}
