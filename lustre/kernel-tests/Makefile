ifeq ($(PATCHLEVEL),)

ifneq ($(LUSTRE_LINUX_CONFIG),)
include $(LUSTRE_LINUX_CONFIG)
endif
include Makefile

else

ifneq ($(LUSTRE_KERNEL_TEST),)
ifeq ($(PATCHLEVEL),4)
all: $(LUSTRE_KERNEL_TEST)
else
extra-y = $(LUSTRE_KERNEL_TEST)
endif
endif

obj-m := conftest.o

ifeq ($(PATCHLEVEL),4)
include $(TOPDIR)/Rules.make
endif

endif
