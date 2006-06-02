# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
sbin_SCRIPTS = lustre_config.sh lc_modprobe.sh lc_net.sh lc_hb.sh lc_mon.sh lc_cluman.sh lc_servip.sh lustre_createcsv.sh

EXTRA_DIST = $(sbin_SCRIPTS) license-status maketags.sh lustre lustrefs \
        version_tag.pl.in

initddir = $(sysconfdir)/init.d
if UTILS
initd_SCRIPTS = lustre lustrefs
endif

