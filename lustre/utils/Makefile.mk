include $(src)/../portals/Kernelenv

LIBPTLCTL := -L$(src)/../portals/utils -lptlctl

host-progs := lctl lfind lstripe obdio obdbarrier obdstat lload
always := $(host-progs)

lctl-objs := parser.o obd.o lctl.o
HOSTLOADLIBES_lctl += $(LIBREADLINE) $(LIBPTLCTL)
obdio-objs := obdio.o obdiolib.o
obdbarrier-objs := obdbarrier.o obdiolib.o
lload-objs := lload.o
HOSTLOADLIBES_lload += $(LIBPTLCTL)

