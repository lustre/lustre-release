# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

AUTOMAKE_OPTIONS = foreign

if LINUX25
DIRS24 = 
else
DIRS24 = extN ptlbd
endif

if LIBLUSTRE
SUBDIRS = lov obdclass ptlrpc obdecho ldlm osc liblustre utils
else
# NOTE: keep extN before obdclass, mds, and obdfilter.  Keep obdclass as early
# as possible, to have the best chance at stopping with "wrong kernel version"
# instead of some related build failure.
SUBDIRS = $(DIRS24) obdclass mds utils ptlrpc ldlm lib obdfilter mdc osc ost
SUBDIRS+= llite obdecho lov cobd tests doc scripts conf
endif

DIST_SUBDIRS = $(SUBDIRS)
EXTRA_DIST = BUGS FDL Rules include archdep.m4 kernel_patches

# We get the version from the spec file.
CONFIGURE_DEPENDENCIES = scripts/lustre.spec.in

dist-hook:
	find $(distdir) -name .deps | xargs rm -rf
	find $(distdir) -name CVS | xargs rm -rf

include $(top_srcdir)/Rules

rpms: dist Makefile
	rpmbuild -ta $(distdir).tar.gz
