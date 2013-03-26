#
# There are four ways this Makefile can be called:
#
#
# 1.  As a subdirectory from the toplevel, for automake
#
# 2.  A wrapper around the kernel's makefile when building modules, to
#     possibly override the .config file
#
# 3.  At configure time, as the toplevel module dir for building
#     kernel tests
#
# 4.  At configure time, to determine the kernel's idea of $(ARCH)
#

ifeq ($(PATCHLEVEL),)

ifeq ($(LUSTRE_LINUX_CONFIG),)

# case #1
include autoMakefile

else

# case #2
# Note that this comes from make -C $LINUX -f $LUSTRE/build/Makefile
# so "include Makefile" below includes $LINUX/Makefile, not this file
include $(LUSTRE_LINUX_CONFIG)
include Makefile

endif # LUSTRE_LINUX_CONFIG

else # PATCHLEVEL

# case 3

ifneq ($(LUSTRE_KERNEL_TEST),)
extra-y = $(LUSTRE_KERNEL_TEST)
endif

obj-m := conftest.o

endif # PATCHLEVEL

# case 4

echoarch:
	echo $(ARCH) >$(ARCHFILE)
