// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>

/* [МЕТКА 1: Машинный код капсулы внутри EPT: штатный OUT 0x10 и попытка чтения за границей 0x5000] */
static const uint8_t *guest_code = (const uint8_t[]){
    0xb8, 0x45, 0x5a,       /* mov ax, 0x5a45 ('ZE') */
    0xe7, 0x10,             /* out 0x10, ax  -> VM-Exit #1 (KVM_EXIT_IO) */
    0xbb, 0x00, 0x50,       /* mov bx, 0x5000 (адрес вне разрешённой EPT-страницы) */
    0x8b, 0x07,             /* mov ax, [bx]  -> VM-Exit #2 (EPT Violation / KVM_EXIT_MMIO) */
    0xf4                    /* hlt */
};

int main(void) {
    /* [МЕТКА 2: Инициализация аппаратного гипервизора KVM / Intel VT-x с проверкой всех дескрипторов] */
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) { perror("open /dev/kvm"); return 1; }

    int vmfd = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vmfd < 0) { close(kvm); return 2; }

    uint8_t *ept_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ept_page == MAP_FAILED) { close(vmfd); close(kvm); return 3; }
    memcpy(ept_page, guest_code, 11);

    /* [МЕТКА 3: Привязка единственной 4КБ страницы EPT (0x0..0xFFF) для аппаратной изоляции] */
    struct kvm_userspace_memory_region reg = {
        .slot = 0, .guest_phys_addr = 0x0, .memory_size = 4096, .userspace_addr = (uint64_t)(uintptr_t)ept_page
    };
    if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &reg) < 0) {
        munmap(ept_page, 4096); close(vmfd); close(kvm); return 4;
    }

    int vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    int mmap_raw = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (vcpufd < 0 || mmap_raw <= 0) {
        if (vcpufd >= 0) close(vcpufd);
        munmap(ept_page, 4096); close(vmfd); close(kvm); return 5;
    }
    size_t mmap_sz = (size_t)mmap_raw;
    struct kvm_run *run = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
    if (run == MAP_FAILED) {
        close(vcpufd); munmap(ept_page, 4096); close(vmfd); close(kvm); return 6;
    }

    struct kvm_sregs sregs; struct kvm_regs regs;
    if (ioctl(vcpufd, KVM_GET_SREGS, &sregs) < 0) goto cleanup;
    sregs.cs.base = 0; sregs.cs.selector = 0;
    if (ioctl(vcpufd, KVM_SET_SREGS, &sregs) < 0) goto cleanup;

    memset(&regs, 0, sizeof(regs));
    regs.rip = 0x0; regs.rflags = 0x2;
    if (ioctl(vcpufd, KVM_SET_REGS, &regs) < 0) goto cleanup;

    /* [МЕТКА 4: Запуск капсулы в VMX Non-Root и перехват аппаратных событий VM-Exit] */
    printf("=== СТУПЕНЬ 1: АППАРАТНАЯ ИЗОЛЯЦИЯ INTEL VT-x / EPT (VM-EXIT) ===\n");
    for (int step = 0; step < 2; step++) {
        if (ioctl(vcpufd, KVM_RUN, 0) < 0) break;
        if (run->exit_reason == KVM_EXIT_IO) {
            uint16_t val = *(uint16_t *)((uint8_t *)run + run->io.data_offset);
            printf("VM-Exit #1 (VT-x IO)  : капсула передала подпись 0x%04X ('%c%c') из EPT!\n",
                   val, val & 0xFF, (val >> 8) & 0xFF);
        } else if (run->exit_reason == KVM_EXIT_MMIO) {
            printf("VM-Exit #2 (EPT Trap) : процессор аппаратно пресёк выход за границу EPT по адресу 0x%llx!\n",
                   (unsigned long long)run->mmio.phys_addr);
        }
    }

cleanup:
    munmap(run, mmap_sz); close(vcpufd); munmap(ept_page, 4096); close(vmfd); close(kvm);
    return 0;
}
