KERNEL_VER = $(shell uname -r)

# the file to compile
obj-m += netfiltersample.o

# specify flags for the module compilation
EXTRA_CFLAGS = -g -O0

build: kernel_modules

kernel_modules:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(shell pwd) modules