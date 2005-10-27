EXTRA_CFLAGS := -Ifs/lustre/include -Ifs/lustre/lnet/include
HOSTCFLAGS := $(EXTRA_CFLAGS)
# the kernel doesn't want us to build archives for host binaries :/
PTLCTLOBJS := debug.o l_ioctl.o parser.o portals.o
