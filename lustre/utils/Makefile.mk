include $(src)/../portals/Kernelenv

OURPTLCTL := $(addprefix $(src)/../portals/utils/, $(PTLCTLOBJS))
OURPTLCTLNOPARSER := $(addprefix $(src)/../portals/utils/, \
			$(filter-out parser.o,$(PTLCTLOBJS)))

host-progs := lctl lfind lstripe obdio obdbarrier obdstat lload
always := $(host-progs) 

lctl-objs := parser.o obd.o lctl.o
HOSTLOADLIBES_lctl += $(LIBREADLINE) $(OURPTLCTLNOPARSER)
obdio-objs := obdio.o obdiolib.o
obdbarrier-objs := obdbarrier.o obdiolib.o
lload-objs := lload.o
HOSTLOADLIBES_lload += $(OURPTLCTL)
