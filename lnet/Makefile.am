# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

EXTRA_DIST = Rules.linux archdep.m4 
DIST_SUBDIRS = libcfs portals knals unals utils tests doc router
if LIBLUSTRE
SUBDIRS = portals unals utils
else
SUBDIRS = libcfs portals knals unals utils tests doc router
endif
