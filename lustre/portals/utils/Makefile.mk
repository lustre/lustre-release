include $(src)/../Kernelenv

host-progs := acceptor ptlctl

ptlctl-objs := libptlctl.so ptlctl.o

libptlctl-objs := debug.o l_ioctl.o parser.o portals.o

always := $(host-progs)
