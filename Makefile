KSRC ?= /lib/modules/$(shell uname -r)/build
#KSRC = $(HOME)/linux/

CONFIG_CRYPTO_STREEBOG ?= m

obj-m :=
obj-m += gost28147_generic.o
obj-m += gosthash94_generic.o
obj-m += kuznyechik_generic.o
obj-m += magma_generic.o
obj-$(CONFIG_CRYPTO_STREEBOG) += streebog_generic.o
obj-m += gost-test.o

ifneq ($(filter y,$(CONFIG_X86_64) $(CONFIG_ARM64)),)
obj-m += kuznyechik_simd.o
endif

gost28147_generic-y := gost28147_basic.o gost28147_modes.o
kuznyechik_simd-y := kuznyechik_simd_glue.o
kuznyechik_simd-$(CONFIG_X86_64) += kuznyechik_simd_x86_64.o
kuznyechik_simd-$(CONFIG_ARM64) += kuznyechik_simd_arm64.o
gost-test-y:= testmgr.o gost-test-main.o

ccflags-y := -I $(src)

# Make IS_ENABLED(CONFIG_CRYPTO_STREEBOG) work
ifneq ($(CONFIG_CRYPTO_STREEBOG),n)
ccflags-y += -DCONFIG_CRYPTO_STREEBOG_MODULE=1
endif

all: modules

modules modules_install clean:
	$(MAKE) -C $(KSRC) M=$(CURDIR) $@
