// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>

/* [МЕТКА 1: Машинные опкоды Эпохи 1 (GPA 0x0) и Эпохи 2 (GPA 0x2000 с попыткой чтения старого Слота А)] */
static const uint8_t *code_ep1 = (const uint8_t[]){ 0xb8, 0x01, 0xe0, 0xe7, 0x10, 0xf4 };
static const uint8_t *code_ep2 = (const uint8_t[]){ 0xb8, 0x02, 0xe0, 0xe7, 0x10, 0xbb, 0x00, 0x00, 0x8b, 0x07, 0xf4 };

int main(void) {
    /* [МЕТКА 2: Открытие аппаратного интерфейса Intel VT-x (/dev/kvm) и создание изолированной ВМ] */
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) return 1;
    int vmfd = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vmfd < 0) { close(kvm); return 2; }

    /* [МЕТКА 3: Выделение двух 4КБ страниц под EPT Слот А и Слот Б с проверкой MAP_FAILED] */
    uint8_t *page_a = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t *page_b = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page_a == MAP_FAILED || page_b == MAP_FAILED) {
        if (page_a != MAP_FAILED) munmap(page_a, 4096);
        if (page_b != MAP_FAILED) munmap(page_b, 4096);
        close(vmfd); close(kvm); return 3;
    }
    memcpy(page_a, code_ep1, 6);
    memcpy(page_b, code_ep2, 11);

    /* [МЕТКА 4: Регистрация EPT Слота А (GPA 0x0) и создание виртуального ядра vCPU] */
    struct kvm_userspace_memory_region reg_a = { 0, 0, 0x0, 4096, (uint64_t)(uintptr_t)page_a };
    if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &reg_a) < 0) {
        munmap(page_a, 4096); munmap(page_b, 4096); close(vmfd); close(kvm); return 4;
    }

    int vcpu = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    int rsz_raw = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (vcpu < 0 || rsz_raw <= 0) {
        if (vcpu >= 0) close(vcpu);
        munmap(page_a, 4096); munmap(page_b, 4096); close(vmfd); close(kvm); return 5;
    }
    size_t rsz = (size_t)rsz_raw;
    struct kvm_run *run = mmap(NULL, rsz, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);
    if (run == MAP_FAILED) {
        close(vcpu); munmap(page_a, 4096); munmap(page_b, 4096); close(vmfd); close(kvm); return 6;
    }

    struct kvm_sregs sregs; struct kvm_regs regs;
    if (ioctl(vcpu, KVM_GET_SREGS, &sregs) < 0) goto cleanup;
    sregs.cs.base = 0; sregs.cs.selector = 0;
    if (ioctl(vcpu, KVM_SET_SREGS, &sregs) < 0) goto cleanup;

    memset(&regs, 0, sizeof(regs)); regs.rip = 0x0; regs.rflags = 0x2;
    if (ioctl(vcpu, KVM_SET_REGS, &regs) < 0) goto cleanup;

    printf("=== ШАГ 2: АППАРАТНЫЙ EPT DOUBLE-BUFFER (INTEL VT-x) ===\n");
    if (ioctl(vcpu, KVM_RUN, 0) < 0 || run->exit_reason != KVM_EXIT_IO) goto cleanup;
    uint16_t v1 = *(uint16_t *)((uint8_t *)run + run->io.data_offset);
    printf("Эпоха 1 (EPT Слот А @ 0x0000): активен, код вернул 0x%04X\n", v1);

    /* [МЕТКА 5: Атомарный отзыв EPT Слота А, выжигание памяти и активация EPT Слота Б @ 0x2000] */
    reg_a.memory_size = 0;
    if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &reg_a) < 0) goto cleanup;
    explicit_bzero(page_a, 4096);

    struct kvm_userspace_memory_region reg_b = { 1, 0, 0x2000, 4096, (uint64_t)(uintptr_t)page_b };
    if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &reg_b) < 0) goto cleanup;

    regs.rip = 0x2000;
    if (ioctl(vcpu, KVM_SET_REGS, &regs) < 0) goto cleanup;
    if (ioctl(vcpu, KVM_RUN, 0) < 0 || run->exit_reason != KVM_EXIT_IO) goto cleanup;
    uint16_t v2 = *(uint16_t *)((uint8_t *)run + run->io.data_offset);
    printf("Эпоха 2 (EPT Слот Б @ 0x2000): переключено, код вернул 0x%04X\n", v2);

    /* [МЕТКА 6: Проверка аппаратного перехвата EPT Trap при обращении к отозванному Слоту А] */
    if (ioctl(vcpu, KVM_RUN, 0) >= 0 && run->exit_reason == KVM_EXIT_MMIO) {
        printf("Защита старого слота (EPT Trap): обращение к отключённому Слоту А (0x%llx) пресечено железом!\n",
               (unsigned long long)run->mmio.phys_addr);
    }

cleanup:
    munmap(run, rsz); close(vcpu); munmap(page_a, 4096); munmap(page_b, 4096); close(vmfd); close(kvm);
    return 0;
}
