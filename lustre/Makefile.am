# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

AUTOMAKE_OPTIONS = foreign

# NOTE: keep extN before mds
SUBDIRS = lov utils obdclass ldlm ptlrpc llite lib obdecho mdc osc
SUBDIRS+=  mds ost tests obdfilter doc scripts extN 

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

