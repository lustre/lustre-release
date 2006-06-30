# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
sbin_SCRIPTS = lustre_config.sh lc_modprobe.sh lc_net.sh lc_hb.sh lc_mon.sh lc_cluman.sh lc_servip.sh lustre_createcsv.sh lustre_up14.sh

EXTRA_DIST = license-status maketags.sh version_tag.pl.in lc_common.sh \
	     lustre_config.sh.in lc_modprobe.sh.in lc_net.sh.in lc_hb.sh.in lc_mon.sh \
	     lc_cluman.sh.in lc_servip.sh lustre_createcsv.sh.in lustre_up14.sh

scriptlibdir = $(libdir)/@PACKAGE@
scriptlib_DATA = lc_common.sh

lustre_config.sh: lustre_config.sh.in
	sed -e 's#@scriptlibdir@#$(scriptlibdir)#' < $(srcdir)/lustre_config.sh.in > lustre_config.sh
	chmod +x lustre_config.sh

lc_modprobe.sh: lc_modprobe.sh.in
	sed -e 's#@scriptlibdir@#$(scriptlibdir)#' < $(srcdir)/lc_modprobe.sh.in > lc_modprobe.sh
	chmod +x lc_modprobe.sh

lc_net.sh: lc_net.sh.in
	sed -e 's#@scriptlibdir@#$(scriptlibdir)#' < $(srcdir)/lc_net.sh.in > lc_net.sh
	chmod +x lc_net.sh

lc_hb.sh: lc_hb.sh.in
	sed -e 's#@scriptlibdir@#$(scriptlibdir)#' < $(srcdir)/lc_hb.sh.in > lc_hb.sh
	chmod +x lc_hb.sh

lc_cluman.sh: lc_cluman.sh.in
	sed -e 's#@scriptlibdir@#$(scriptlibdir)#' < $(srcdir)/lc_cluman.sh.in > lc_cluman.sh
	chmod +x lc_cluman.sh

lustre_createcsv.sh: lustre_createcsv.sh.in
	sed -e 's#@scriptlibdir@#$(scriptlibdir)#' < $(srcdir)/lustre_createcsv.sh.in > lustre_createcsv.sh
	chmod +x lustre_createcsv.sh
