obj-m += tuc.o

# KDIR ?= /lib/modules/$(shell uname -r)/build/
KDIR ?= /home/tuto/Downloads/linux-5.4.98/

PWD := $(shell pwd)

EXTRA_CFLAGS += -g  # 添加调试信息

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# obj-m += tuc.o

# all:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# clean:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean