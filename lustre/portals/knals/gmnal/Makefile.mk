# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include ../../Kernelenv

obj-y += gmnal.o
gmnal-objs    := gmnal_api.o gmnal_cb.o gmnal_utils.o gmnal_comm.o gmnal_module.o

