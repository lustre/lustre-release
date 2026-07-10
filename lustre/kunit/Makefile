# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-$(CONFIG_LUSTRE_FS_TESTS) += ec_test.o kinode.o obd_test.o obd_mod_rpcs_test.o
obj-$(CONFIG_LUSTRE_FS_SERVER) += ldlm_extent.o llog_test.o

ifdef CONFIG_GCOV_PROFILE_LUSTRE
GCOV_PROFILE := y
endif
