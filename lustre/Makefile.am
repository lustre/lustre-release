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

# NOTE: keep extN before mds and obdfilter
SUBDIRS = $(DIRS24) obdclass utils ptlrpc ldlm lib obdfilter mdc osc ost llite
SUBDIRS+= obdecho lov cobd ptlbd tests doc scripts conf

DIST_SUBDIRS = $(SUBDIRS)
EXTRA_DIST = BUGS FDL Rules include archdep.m4

# We get the version from the spec file.
CONFIGURE_DEPENDENCIES = scripts/lustre.spec.in

dist-hook:
	find $(distdir) -name .deps | xargs rm -rf
	find $(distdir) -name CVS | xargs rm -rf

include $(top_srcdir)/Rules

rpms: dist Makefile
	rpmbuild -ta $(distdir).tar.gz
