include $(src)/../Kernelenv

host-progs := acceptor ptlctl

ptlctl-objs := debug.o l_ioctl.o parser.o portals.o ptlctl.o

always := $(host-progs)
