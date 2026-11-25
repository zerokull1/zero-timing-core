// ZEROMANI (zerokull1) | Author Signature: 0x5A45524F4D414E49ULL
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

#define ZEROMANI_MAGIC 0x494E414D4F52455AULL
#define HEADER_ALIGN   4096ULL

typedef struct __attribute__((aligned(64))) {
    uint64_t magic;
    uint32_t version;
    uint32_t snaplen;
    uint64_t pkt_count;
    uint64_t quota_bytes;
    uint64_t ring_cursor;
    uint64_t _pad[3];
} dump_header_t;

typedef struct {
    uint64_t w0, w1, w2, w3, w4, w5, w6, w7;
} chunk64_t;

typedef struct __attribute__((aligned(64))) {
    uint64_t tsc;
    uint32_t len;
    uint32_t verdict;
    uint64_t pad0, pad1, pad2, pad3, pad4, pad5;
    chunk64_t c0, c1, c2;
} dump_slot_t;

static inline int sys_io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static inline int sys_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete, unsigned flags) {
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, NULL, 0);
}

int main(void) {
    const size_t BATCH_SLOTS = 1024;
    const size_t RING_BYTES = BATCH_SLOTS * sizeof(dump_slot_t); /* 256 KiB */
    const uint64_t DATA_QUOTA_BYTES = 4ULL * 1024ULL * 1024ULL;  /* 4 MiB power-of-2 ring */
    const uint64_t DATA_RING_MASK   = DATA_QUOTA_BYTES - 1ULL;
    const uint64_t TOTAL_FILE_QUOTA = HEADER_ALIGN + DATA_QUOTA_BYTES;
    const int TOTAL_BATCHES = 64; /* 16 MiB stream -> 4 full ring wraps */

    dump_slot_t *slots = aligned_alloc(4096, RING_BYTES);
    if (!slots) { perror("aligned_alloc"); return 1; }
    memset(slots, 0, RING_BYTES);

    for (size_t i = 0; i < BATCH_SLOTS; i++) {
        dump_slot_t *s = slots + i;
        s->tsc = 1000000ULL + (uint64_t)i * 32ULL;
        s->len = 64;
        s->verdict = 2;
        s->c0.w0 = 0xDEADC0DE00000001ULL | ((uint64_t)i << 8);
    }

    struct io_uring_params p;
    memset(&p, 0, sizeof(p));
    int ring_fd = sys_io_uring_setup(32, &p);
    if (ring_fd < 0) { perror("io_uring_setup"); free(slots); return 1; }

    size_t sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        if (cq_ring_sz > sq_ring_sz) sq_ring_sz = cq_ring_sz;
        cq_ring_sz = sq_ring_sz;
    }

    void *sq_ptr = mmap(0, sq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING);
    struct io_uring_sqe *sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES);
    if (sq_ptr == MAP_FAILED || sqes == MAP_FAILED) { perror("mmap io_uring"); return 1; }

    unsigned *sq_tail = (unsigned *)((char *)sq_ptr + p.sq_off.tail);
    unsigned *sq_mask = (unsigned *)((char *)sq_ptr + p.sq_off.ring_mask);
    unsigned *sq_array = (unsigned *)((char *)sq_ptr + p.sq_off.array);

    const char *dump_path = "/tmp/zero_forensic_flight.zcap";
    unlink(dump_path);
    int out_fd = open(dump_path, O_CREAT | O_RDWR | O_NOFOLLOW | O_TRUNC, 0600);
    if (out_fd < 0) { perror("open dump"); return 1; }
    if (ftruncate(out_fd, (off_t)TOTAL_FILE_QUOTA) != 0) { perror("ftruncate quota"); return 1; }

    dump_header_t hdr = {
        .magic = ZEROMANI_MAGIC,
        .version = 2,
        .snaplen = (uint32_t)sizeof(dump_slot_t),
        .pkt_count = (uint64_t)BATCH_SLOTS * (uint64_t)TOTAL_BATCHES,
        .quota_bytes = TOTAL_FILE_QUOTA,
        .ring_cursor = 0
    };
    if (pwrite(out_fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr)) { perror("pwrite hdr"); return 1; }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint64_t ring_cursor = 0;
    for (int batch = 0; batch < TOTAL_BATCHES; batch++) {
        unsigned tail = *sq_tail;
        unsigned idx = tail & *sq_mask;
        struct io_uring_sqe *sqe = sqes + idx;
        memset(sqe, 0, sizeof(*sqe));
        sqe->opcode = IORING_OP_WRITE;
        sqe->fd = out_fd;
        sqe->off = HEADER_ALIGN + (ring_cursor & DATA_RING_MASK);
        sqe->addr = (uint64_t)(uintptr_t)slots;
        sqe->len = (uint32_t)RING_BYTES;

        *(sq_array + idx) = idx;
        __atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);

        if (sys_io_uring_enter(ring_fd, 1, 1, IORING_ENTER_GETEVENTS) < 0) {
            perror("io_uring_enter");
            return 1;
        }
        ring_cursor += RING_BYTES;
    }

    hdr.ring_cursor = ring_cursor;
    if (pwrite(out_fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr)) { perror("pwrite final hdr"); return 1; }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
    double stream_mb = (double)ring_cursor / (1024.0 * 1024.0);

    struct stat st;
    if (fstat(out_fd, &st) != 0 || (uint64_t)st.st_size != TOTAL_FILE_QUOTA) {
        fprintf(stderr, "Нарушение жёсткой квоты файла на диске!\n");
        return 1;
    }

    close(out_fd);
    close(ring_fd);

    int vfd = open(dump_path, O_RDONLY | O_NOFOLLOW);
    dump_header_t check_hdr;
    if (vfd < 0 || pread(vfd, &check_hdr, sizeof(check_hdr), 0) != (ssize_t)sizeof(check_hdr) || check_hdr.magic != ZEROMANI_MAGIC) {
        fprintf(stderr, "Ошибка проверки авторской подписи дампа!\n");
        return 1;
    }
    close(vfd);
    unlink(dump_path);
    free(slots);

    printf("=== БОРТСАМОПИСЕЦ ДАМПОВ (IO_URING + ЖЁСТКАЯ КОЛЬЦЕВАЯ КВОТА ДИСКА) ===\n");
    printf("Авторская метка : %.8s (подтверждена)\n", (char *)&check_hdr.magic);
    printf("Поток дампа     : %llu кадров (%.2f МБ) за %.4f сек\n",
           (unsigned long long)check_hdr.pkt_count, stream_mb, sec);
    printf("Квота на диске  : %.2f МБ (оборотов кольца: %llu, размер файла строго в квоте [OK])\n",
           (double)st.st_size / (1024.0 * 1024.0),
           (unsigned long long)(check_hdr.ring_cursor / DATA_QUOTA_BYTES));
    printf("Скорость сброса : %.2f МБ/с (%.2f млн кадров/сек)\n",
           stream_mb / sec, (check_hdr.pkt_count / 1e6) / sec);
    return 0;
}
