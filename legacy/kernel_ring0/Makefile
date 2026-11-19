# ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
obj-m += zero_timing_ring0.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
