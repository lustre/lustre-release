include $(src)/../Kernelenv

host-progs := acceptor ptlctl
always := $(host-progs)

ptlctl-objs := ptlctl.o $(PTLCTLOBJS)
