#include "../ddr_arena/ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const uint32_t *k256 = (const uint32_t[]){
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static const uint32_t *iv256 = (const uint32_t[]){
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

static void sha256_raw(const uint8_t *msg, size_t len, uint8_t *out32) {
    uint32_t *st = __builtin_alloca(32); memcpy(st, iv256, 32);
    uint8_t *blk = __builtin_alloca(128); memset(blk, 0, 128);
    uint32_t *w  = __builtin_alloca(256);
    memcpy(blk, msg, len); *(blk + len) = 0x80;
    uint64_t bits = (uint64_t)len * 8ULL;
    for (int i = 0; i < 8; i++) *(blk + 120 + i) = (uint8_t)(bits >> (56 - i * 8));

    for (size_t off = 0; off < 128; off += 64) {
        const uint8_t *chunk = blk + off;
        for (int i = 0; i < 16; i++)
            *(w + i) = ((uint32_t)*(chunk+i*4)<<24)|((uint32_t)*(chunk+i*4+1)<<16)|((uint32_t)*(chunk+i*4+2)<<8)|*(chunk+i*4+3);
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROTR32(*(w+i-15),7)^ROTR32(*(w+i-15),18)^(*(w+i-15)>>3);
            uint32_t s1 = ROTR32(*(w+i-2),17)^ROTR32(*(w+i-2),19)^(*(w+i-2)>>10);
            *(w+i) = *(w+i-16) + s0 + *(w+i-7) + s1;
        }
        uint32_t a=*(st+0),b=*(st+1),c=*(st+2),d=*(st+3),e=*(st+4),f=*(st+5),g=*(st+6),h=*(st+7);
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ROTR32(e,6)^ROTR32(e,11)^ROTR32(e,25), ch = (e&f)^((~e)&g), t1 = h+S1+ch+*(k256+i)+*(w+i);
            uint32_t S0 = ROTR32(a,2)^ROTR32(a,13)^ROTR32(a,22), maj = (a&b)^(a&c)^(b&c), t2 = S0+maj;
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        *(st+0)+=a; *(st+1)+=b; *(st+2)+=c; *(st+3)+=d; *(st+4)+=e; *(st+5)+=f; *(st+6)+=g; *(st+7)+=h;
    }
    for (int i = 0; i < 8; i++) {
        *(out32+i*4)=(uint8_t)(*(st+i)>>24); *(out32+i*4+1)=(uint8_t)(*(st+i)>>16);
        *(out32+i*4+2)=(uint8_t)(*(st+i)>>8); *(out32+i*4+3)=(uint8_t)*(st+i);
    }
}

static void hmac_sha256_32(const uint8_t *key32, const uint8_t *data, size_t len, uint8_t *mac32) {
    if (!key32 || !data || !mac32 || len > 55) return;
    uint8_t *buf_in = __builtin_alloca(128), *buf_out = __builtin_alloca(128), *inner = __builtin_alloca(32);
    for (int i = 0; i < 32; i++) { *(buf_in+i) = *(key32+i) ^ 0x36; *(buf_out+i) = *(key32+i) ^ 0x5c; }
    memset(buf_in + 32, 0x36, 32); memset(buf_out + 32, 0x5c, 32);
    memcpy(buf_in + 64, data, len);
    sha256_raw(buf_in, 64 + len, inner);
    memcpy(buf_out + 64, inner, 32);
    sha256_raw(buf_out, 96, mac32);
    explicit_bzero(buf_in, 128); explicit_bzero(buf_out, 128);
}

static int ct_memeq32(const uint8_t *a, const uint8_t *b) {
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= (*(a + i) ^ *(b + i));
    return diff == 0;
}

typedef uint64_t (*capsule_fn_t)(uint64_t x);

int main(void) {
    const uint8_t *epoch_key = (const uint8_t *)"ZEROMANI_256BIT_EPOCH_ROOT_KEY!!";
    const uint8_t *good_code = (const uint8_t[]){ 0x48,0x89,0xf8, 0x48,0x35,0x45,0x5a,0x00,0x00, 0xc3,0x90,0x90,0x90,0x90,0x90,0x90 };
    uint8_t *valid_mac = __builtin_alloca(32), *calc_mac = __builtin_alloca(32);
    hmac_sha256_32(epoch_key, good_code, 16, valid_mac);

    uint8_t *tampered_code = __builtin_alloca(16);
    memcpy(tampered_code, good_code, 16);
    *(tampered_code + 5) ^= 0x01;
    hmac_sha256_32(epoch_key, tampered_code, 16, calc_mac);
    int tamper_rejected = !ct_memeq32(valid_mac, calc_mac);

    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;
    hmac_sha256_32(epoch_key, good_code, 16, calc_mac);
    if (!ct_memeq32(valid_mac, calc_mac)) { ddr_arena_destroy(&arena); return 2; }

    size_t off = (size_t)ddr_arena_push_code(&arena, good_code, 16);
    if (!off || ddr_arena_seal_wx(&arena) != 0) return 3;

    capsule_fn_t fn = (capsule_fn_t)(arena.base + off);
    uint64_t res = fn(0x10000ULL);

    printf("=== ЗАЩИТА №3: HMAC-SHA256 КАПСУЛЫ ДО ВЫДЕЛЕНИЯ PROT_EXEC ===\n");
    printf("Подмена 1 бита в капсуле : %s (PROT_EXEC не выдан!)\n", tamper_rejected ? "ОТБИТА (HMAC MISMATCH)" : "ОШИБКА");
    printf("Валидная капсула (256b)  : HMAC-SHA256 OK -> W^X PROT_EXEC выдан, результат=0x%llx\n", (unsigned long long)res);

    ddr_arena_destroy(&arena);
    return (tamper_rejected && res == 0x15A45ULL) ? 0 : 4;
}
