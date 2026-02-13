# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += osd_ldiskfs.o
osd_ldiskfs-objs := osd_handler.o osd_oi.o osd_lproc.o osd_iam.o \
		    osd_iam_lfix.o osd_iam_lvar.o osd_io.o osd_compat.o \
		    osd_scrub.o osd_dynlocks.o osd_quota.o osd_quota_fmt.o \
		    osd_integrity.o

ccflags-y := -I$(LINUX)/fs -I$(ABS_TOP_BUILDDIR) -I$(ABS_TOP_BUILDDIR)/ldiskfs
