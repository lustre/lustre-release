# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += lnet_selftest.o

lnet_selftest-objs := console.o conrpc.o conctl.o framework.o timer.o rpc.o \
		      module.o ping_test.o brw_test.o

ifdef CONFIG_GCOV_PROFILE_LNET
GCOV_PROFILE := y
endif
