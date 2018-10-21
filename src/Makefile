ccflags-y := -DDBG -g
obj-m := panop.o
panop-objs := init.o

MOD_DIR = /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(MOD_DIR)	M=$(PWD) modules
clean:
	rm -rf *.o *.ko *.symvers *.mod.* *.order
