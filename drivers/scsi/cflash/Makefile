obj-$(CONFIG_CFLASH) += cflash.o
cflash-y += cflash_main.o cflash_mc.o cflash_ba.o

KBUILD_EXTRA_SYMBOLS = $(MY_KERNEL_SRC)/drivers/misc/cxl/Module.symvers
ccflags-y += -DCONFIG_PRINTK
