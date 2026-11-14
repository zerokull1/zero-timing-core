#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>

// Код Эпохи 1 (GPA 0x0): отдаёт 0xE001 через OUT 0x10, AX
static const uint8_t *code_ep1 = (const uint8_t[]){ 0xb8, 0x01, 0xe0, 0xe7, 0x10, 0xf4 };
// Код Эпохи 2 (GPA 0x2000): отдаёт 0xE002 через OUT 0x10, AX, затем пытается прочитать старый GPA 0x0 (EPT Trap!)
static const uint8_t *code_ep2 = (const uint8_t[]){ 0xb8, 0x02, 0xe0, 0xe7, 0x10, 0xbb, 0x00, 0x00, 0x8b, 0x07, 0xf4 };

int main() {
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) return 1;
    int vmfd = ioctl(kvm, KVM_CREATE_VM, 0);

    uint8_t *page_a = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t *page_b = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(page_a, code_ep1, 6);
    memcpy(page_b, code_ep2, 11);

    // 1. Включаем EPT Слот А (GPA 0x0)
    struct kvm_userspace_memory_region reg_a = { 0, 0, 0x0, 4096, (uint64_t)page_a };
    ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &reg_a);

    int vcpu = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    size_t rsz = (size_t)ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    struct kvm_run *run = mmap(NULL, rsz, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);

    struct kvm_sregs sregs; struct kvm_regs regs;
    ioctl(vcpu, KVM_GET_SREGS, &sregs);
    sregs.cs.base = 0; sregs.cs.selector = 0;
    ioctl(vcpu, KVM_SET_SREGS, &sregs);

    memset(&regs, 0, sizeof(regs)); regs.rip = 0x0; regs.rflags = 0x2;
    ioctl(vcpu, KVM_SET_REGS, &regs);

    printf("=== ШАГ 2: АППАРАТНЫЙ EPT DOUBLE-BUFFER (INTEL VT-x) ===\n");
    ioctl(vcpu, KVM_RUN, 0);
    uint16_t v1 = *(uint16_t *)((uint8_t *)run + run->io.data_offset);
    printf("Эпоха 1 (EPT Слот А @ 0x0000): активен, код вернул 0x%04X\n", v1);

    // 2. Атомарно отключаем EPT Слот А в контроллере памяти и включаем EPT Слот Б @ 0x2000!
    reg_a.memory_size = 0;
    ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &reg_a);
    explicit_bzero(page_a, 4096);

    struct kvm_userspace_memory_region reg_b = { 1, 0, 0x2000, 4096, (uint64_t)page_b };
    ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &reg_b);

    regs.rip = 0x2000;
    ioctl(vcpu, KVM_SET_REGS, &regs);

    ioctl(vcpu, KVM_RUN, 0);
    uint16_t v2 = *(uint16_t *)((uint8_t *)run + run->io.data_offset);
    printf("Эпоха 2 (EPT Слот Б @ 0x2000): переключено, код вернул 0x%04X\n", v2);

    ioctl(vcpu, KVM_RUN, 0);
    if (run->exit_reason == KVM_EXIT_MMIO) {
        printf("Защита старого слота (EPT Trap): обращение к отключённому Слоту А (0x%llx) пресечено железом!\n",
               (unsigned long long)run->mmio.phys_addr);
    }

    munmap(run, rsz); close(vcpu); munmap(page_a, 4096); munmap(page_b, 4096); close(vmfd); close(kvm);
    return 0;
}
