# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-$(CONFIG_LNET_GNILND) += gnilnd/
obj-$(CONFIG_LNET_O2IBLND) += in-kernel-o2iblnd/
ifneq ($(BUILD_EXT_O2IB),)
obj-m += o2iblnd/
endif
obj-$(CONFIG_LNET_KFILND) += kfilnd/
obj-$(CONFIG_LNET_EFALND) += efalnd/
obj-m += socklnd/
