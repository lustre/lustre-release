# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

sbinscripts = lc_servip.sh lustre_up14.sh lustre_rmmod.sh

# These are scripts that are generated from .in files
genscripts = lustre_config.sh lc_modprobe.sh lc_net.sh lc_hb.sh lc_cluman.sh lustre_createcsv.sh lc_md.sh lc_lvm.sh

sbin_SCRIPTS = $(genscripts) $(sbinscripts)
bin_SCRIPTS = lustre_req_history.sh

EXTRA_DIST = license-status maketags.sh version_tag.pl.in lc_common.sh \
	     $(addsuffix .in,$(genscripts)) lc_mon.sh $(sbinscripts) \
	     $(bin_SCRIPTS)

scriptlibdir = $(libdir)/@PACKAGE@
scriptlib_DATA = lc_common.sh

CLEANFILES = $(genscripts)

$(genscripts): %.sh: %.sh.in
	sed -e 's#@scriptlibdir@#$(scriptlibdir)#' < $< > $@
	chmod +x $@
