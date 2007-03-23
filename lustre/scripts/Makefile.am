# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

sbinscripts = lc_servip lustre_up14 lustre_rmmod

# These are scripts that are generated from .in files
genscripts = lustre_config lc_modprobe lc_net lc_hb lc_cluman lustre_createcsv lc_md lc_lvm

sbin_SCRIPTS = $(genscripts) $(sbinscripts)
bin_SCRIPTS = lustre_req_history

EXTRA_DIST = license-status maketags.sh version_tag.pl.in lc_common \
	     $(addsuffix .in,$(genscripts)) lc_mon $(sbinscripts) \
	     $(bin_SCRIPTS)

scriptlibdir = $(libdir)/@PACKAGE@
scriptlib_DATA = lc_common

CLEANFILES = $(genscripts)

$(genscripts): %: %.in
	sed -e 's#@scriptlibdir@#$(scriptlibdir)#' < $< > $@
	chmod +x $@
