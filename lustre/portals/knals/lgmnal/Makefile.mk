# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include ../../Kernelenv

obj-y += lgmnal.o
lgmnal-objs    := lgmnal_api.o lgmnal_cb.o lgmnal_utils.o lgmnal_comm.o lgmnal_module.o

