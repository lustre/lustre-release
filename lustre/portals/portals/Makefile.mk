# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include ../Kernelenv

obj-y += portals.o
portals-objs    := lib-dispatch.o lib-eq.o lib-init.o lib-md.o lib-me.o lib-move.o lib-msg.o lib-ni.o lib-not-impl.o lib-pid.o api-eq.o api-errno.o api-init.o api-md.o api-me.o api-ni.o api-wrap.o
