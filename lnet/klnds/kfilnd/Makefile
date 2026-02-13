# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += kkfilnd.o

kkfilnd-objs := \
	kfilnd.o \
	kfilnd_modparams.o \
	kfilnd_tn.o \
	kfilnd_ep.o \
	kfilnd_dev.o \
	kfilnd_dom.o \
	kfilnd_peer.o \
	kfilnd_cq.o \
	kfilnd_debugfs.o

ccflags-y += $(KFICPPFLAGS)
