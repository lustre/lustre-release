# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

AUTOMAKE_OPTIONS = foreign
SUBDIRS = ptlrpc llite lib ldlm obdecho mdc osc extN mds ost utils tests obdfilter
SUBDIRS+= obdclass obdext2 obdfs demos doc scripts 
EXTRA_DIST = BUGS FDL Rules include patches

# We get the version from the spec file.
configure: scripts/lustre.spec.in

dist-hook:
	find $(distdir) -name .deps | xargs rm -rf

include $(top_srcdir)/Rules
