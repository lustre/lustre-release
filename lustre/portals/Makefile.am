# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

EXTRA_DIST = archdep.m4 build.m4 include 

SUBDIRS = portals
DIST_SUBDIRS =

if LIBLUSTRE
SUBDIRS += unals
else
DIST_SUBDIRS += unals
endif

if MODULES
SUBDIRS += libcfs
if CRAY_PORTALS
DIST_SUBDIRS += knals router
else
SUBDIRS += knals router
endif
SUBDIRS += tests
else
DIST_SUBDIRS += libcfs knals router tests
endif

if DOC
SUBDIRS += doc
else
DIST_SUBDIRS += doc
endif

if UTILS
SUBDIRS += utils
else
DIST_SUBDIRS += utils
endif

DIST_SUBDIRS += $(SUBDIRS)
