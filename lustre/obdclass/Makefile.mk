# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include $(src)/../portals/Kernelenv

obj-y += obdclass.o fsfilt_ext3.o
obdclass-objs := class_obd.o debug.o genops.o sysctl.o uuid.o simple.o\
		lprocfs_status.o lustre_handles.o lustre_peer.o fsfilt.o \
		statfs_pack.o

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
