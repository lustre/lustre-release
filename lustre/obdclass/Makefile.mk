# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += obdclass.o
obdclass-objs := llog.o llog_cat.o class_obd.o debug.o \
		genops.o sysctl.o uuid.o lprocfs_status.o lustre_handles.o \
		lustre_peer.o statfs_pack.o obdo.o llog_lvfs.o llog_obd.o \
		obd_config.o llog_ioctl.o

$(obj)/class_obd.o: lustre_build_version

# XXX I'm sure there's some automake mv-if-different helper for this.
.PHONY:
lustre_build_version:
	pwd
	perl $(src)/../scripts/version_tag.pl $(src)/.. $(obj)/.. > $(obj)/tmpver
	cmp -s $(src)/../include/linux/lustre_build_version.h $(obj)/tmpver \
		2> /dev/null &&                                            \
		$(RM) $(obj)/tmpver ||                                            \
		mv $(obj)/tmpver $(src)/../include/linux/lustre_build_version.h
