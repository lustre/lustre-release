include $(src)/../portals/Kernelenv

OURPTLCTL := $(addprefix $(src)/../portals/utils/, $(PTLCTLOBJS))
OURPTLCTLNOPARSER := $(addprefix $(src)/../portals/utils/, \
			$(filter-out parser.o,$(PTLCTLOBJS)))

host-progs := lctl obdio obdbarrier lload llmount #lfs# obdstat lfind
always := $(host-progs) 

lctl-objs := parser.o obd.o lctl.o lustre_cfg.o
HOSTLOADLIBES_lctl += $(LIBREADLINE) $(OURPTLCTLNOPARSER)
obdio-objs := obdio.o obdiolib.o
obdbarrier-objs := obdbarrier.o obdiolib.o
lload-objs := lload.o
llmount-objs := llmount.o 
HOSTLOADLIBES_llmount += $(OURPTLCTL)
HOSTLOADLIBES_lload += $(OURPTLCTL)
