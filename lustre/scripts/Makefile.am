# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

EXTRA_DIST = license-status maketags.sh lustre.spec version_tag.pl.in	\
	lustre lustrefs lustre.spec.in lustre-kernel-2.4.spec.in	\
	lmake linux-merge-config.awk linux-merge-modules.awk		\
	linux-rhconfig.h suse-functions.sh suse-postun.sh suse-post.sh  \
	suse-trigger-script.sh.in

initddir = $(sysconfdir)/init.d
if UTILS
if INIT_SCRIPTS
initd_SCRIPTS = lustre lustrefs
endif
endif

