# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

AUTOMAKE_OPTIONS = foreign

if LINUX25
DIRS24 = 
else
DIRS24 = ptlbd
endif

if LIBLUSTRE
SUBDIRS = portals obdclass lov ptlrpc obdecho ldlm osc utils mdc #liblustre
else
# NOTE: keep extN before obdclass, mds, and obdfilter.  Keep obdclass as early
# as possible, to have the best chance at stopping with "wrong kernel version"
# instead of some related build failure.
SUBDIRS = portals obdclass $(DIRS24) mds utils ldlm obdfilter mdc osc ost
SUBDIRS+= llite obdecho lov cobd tests doc scripts conf ptlrpc
endif

DIST_SUBDIRS = $(SUBDIRS) liblustre
EXTRA_DIST = BUGS FDL Rules include kernel_patches

# We get the version from the spec file.
CONFIGURE_DEPENDENCIES = scripts/lustre.spec.in

dist-hook:
	find $(distdir) -name .deps | xargs rm -rf
	find $(distdir) -name CVS | xargs rm -rf

include $(top_srcdir)/Rules

rpms: dist Makefile
	rpmbuild -ta $(distdir).tar.gz

