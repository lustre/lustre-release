# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

AUTOMAKE_OPTIONS = foreign
SUBDIRS = rpc llight lib ldlm obdecho mdc osc mds ost utils tests filterobd
SUBDIRS+= class ext2obd obdfs obdtrace demos doc scripts extN
#SUBDIRS+= oraid1 rpctarget inofs rpcclient tests snap
EXTRA_DIST = BUGS FDL Rules include patches

# We get the version from the spec file.
configure: scripts/lustre.spec.in

dist-hook:
	find $(distdir) -name .deps | xargs rm -rf

include $(top_srcdir)/Rules
