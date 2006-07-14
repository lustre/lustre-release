# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

# These are scripts that are generated from .in files
genscripts = lustre_config.sh lc_modprobe.sh lc_net.sh lc_hb.sh lc_cluman.sh lustre_createcsv.sh lc_md.sh lc_lvm.sh

sbin_SCRIPTS = $(genscripts) lc_servip.sh lustre_up14.sh

EXTRA_DIST = license-status maketags.sh version_tag.pl.in lc_common.sh \
	     $(addsuffix .in,$(genscripts)) lc_mon.sh lc_servip.sh \
	     lustre_up14.sh

scriptlibdir = $(libdir)/@PACKAGE@
scriptlib_DATA = lc_common.sh

CLEANFILES = $(genscripts)

$(genscripts): %.sh: %.sh.in
	sed -e 's#@scriptlibdir@#$(scriptlibdir)#' < $< > $@
	chmod +x $@
