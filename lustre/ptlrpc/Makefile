# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += ptlrpc.o
LDLM := ../ldlm/
TARGET := ../target/

ptlrpc_objs := client.o recover.o connection.o niobuf.o pack_generic.o
ptlrpc_objs += events.o ptlrpc_module.o service.o pinger.o
ptlrpc_objs += llog_net.o llog_client.o import.o ptlrpcd.o
ptlrpc_objs += pers.o lproc_ptlrpc.o wiretest.o layout.o
ptlrpc_objs += sec.o sec_ctx.o sec_gc.o sec_config.o sec_lproc.o
ptlrpc_objs += sec_null.o sec_plain.o nrs.o nrs_fifo.o nrs_delay.o heap.o
ptlrpc_objs += errno.o batch.o

nrs_server_objs := nrs_crr.o nrs_orr.o nrs_tbf.o

nodemap_objs := nodemap_handler.o nodemap_lproc.o nodemap_range.o
nodemap_objs += nodemap_idmap.o nodemap_member.o nodemap_storage.o
nodemap_objs += nodemap_fileset_alt.o

-include $(src)/../ldlm/Makefile
ifdef CONFIG_LUSTRE_FS_SERVER
-include $(src)/../target/Makefile
endif

ptlrpc-objs := $(ptlrpc_objs)
ptlrpc-objs += $(patsubst %,$(LDLM)%,$(ldlm_objs))
ifdef CONFIG_LUSTRE_FS_SERVER
ptlrpc-objs += $(nodemap_objs) $(nrs_server_objs)
ptlrpc-objs += pack_server.o llog_server.o
ptlrpc-objs += $(patsubst %,$(TARGET)%,$(target_objs))
endif

obj-$(CONFIG_LUSTRE_FS_GSS) += gss/

ccflags-y := -I$(LUSTRE)/ldlm -I$(LUSTRE)/target
