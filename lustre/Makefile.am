# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

AUTOMAKE_OPTIONS = foreign

if LINUX25
DIRS24 = mds
else
DIRS24 = extN mds
endif

# NOTE: keep extN before mds
SUBDIRS = lov utils obdclass ldlm ptlrpc lib obdecho mdc osc ost llite 
SUBDIRS+=   $(DIRS24) mds obdfilter tests doc scripts 

DIST_SUBDIRS = $(SUBDIRS)
EXTRA_DIST = BUGS FDL Rules include patches archdep.m4

# We get the version from the spec file.
CONFIGURE_DEPENDENCIES = scripts/lustre.spec.in

dist-hook:
	find $(distdir) -name .deps | xargs rm -rf
	find $(distdir) -name CVS | xargs rm -rf

include $(top_srcdir)/Rules

rpms: dist Makefile
	rpm -ta $(distdir).tar.gz

