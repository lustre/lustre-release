# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-$(CONFIG_LNET_GNILND) += gnilnd/

#
# ko2iblnd has two build trees. in-kernel-o2iblnd/ is an out-of-tree
# artifact: its sources are generated from o2iblnd/ by 'make sources' and
# built against the kernel's own RDMA stack (CONFIG_LNET_O2IBLND, set by
# configure when BUILT_IN_KO2IBLND). o2iblnd/ is built against an external
# OFED in a separate kbuild pass (BUILD_EXT_O2IB, see the top-level
# Makefile) or natively when Lustre is part of the kernel tree. Both are
# gated by CONFIG_LNET_XPRT_IB.
#
obj-$(CONFIG_LNET_O2IBLND) += in-kernel-o2iblnd/
ifdef LUSTRE_OOT_BUILD
ifneq ($(BUILD_EXT_O2IB),)
obj-$(CONFIG_LNET_XPRT_IB) += o2iblnd/
endif
else
obj-$(CONFIG_LNET_XPRT_IB) += o2iblnd/
endif

obj-$(CONFIG_LNET_KFILND) += kfilnd/
obj-$(CONFIG_LNET_EFALND) += efalnd/
obj-$(CONFIG_LNET_SOCKLND) += socklnd/
