obj-m += driver.o

# KDIR ?= /lib/modules/$(shell uname -r)/build/
KDIR ?= /home/tuto/Downloads/linux-5.4.98/

PWD := $(shell pwd)

EXTRA_CFLAGS += -masm=intel -g -fno-stack-protector # 添加调试信息

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean