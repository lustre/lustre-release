# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += kgnilnd.o

kgnilnd-objs := gnilnd.o gnilnd_cb.o gnilnd_modparams.o gnilnd_debug.o gnilnd_proc.o \
		gnilnd_sysctl.o gnilnd_stack.o gnilnd_conn.o

ccflags-y := -D"SVN_CODE_REV=KBUILD_STR(${SVN_CODE_REV})" $(GNICPPFLAGS)
