#
# GPL HEADER START
#
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 only,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License version 2 for more details (a copy is included
# in the LICENSE file that accompanied this code).
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; If not, see
# http://www.gnu.org/licenses/gpl-2.0.html
#
# GPL HEADER END
#

#
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2013, 2015, Intel Corporation.
#

#
# This file is part of Lustre, http://www.lustre.org/
# Lustre is a trademark of Sun Microsystems, Inc.
#

# These are scripts that are generated from .in files
genscripts = lc_modprobe lc_net lc_hb lc_cluman lc_md lc_lvm lustre_start lnet

SUBDIRS = systemd

sbin_SCRIPTS = lustre_rmmod ko2iblnd-probe

if RHEL
initdir = $(sysconfdir)/init.d
init_SCRIPTS  = lsvcgss

if !HAVE_SYSTEMD
init_SCRIPTS += lnet
endif

if SERVER
init_SCRIPTS += lustre
endif
endif

if UTILS
sbin_SCRIPTS += ldev lustre_routes_config lustre_routes_conversion
bin_SCRIPTS   = lfs_migrate

if SERVER
sbin_SCRIPTS += $(genscripts) lc_mon lhbadm lc_servip
bin_SCRIPTS  += lustre_req_history

hadir = $(sysconfdir)/ha.d/resource.d
ha_SCRIPTS = Lustre.ha_v2

scriptlibdir = @libexecdir@/@PACKAGE@
scriptlib_SCRIPTS = haconfig
scriptlib_DATA = lc_common
endif # SERVER

if ZFS_ENABLED
sbin_SCRIPTS += zfsobj2fid
endif

endif # UTILS

EXTRA_DIST = license-status lustre_rmmod ldev lc_mon lhbadm \
	     lc_servip lustre_routes_config lustre_routes_conversion \
	     $(addsuffix .in,$(genscripts)) lfs_migrate lustre_req_history \
	     lustre lsvcgss lc_common haconfig Lustre.ha_v2 dkms.mkconf \
	     zfsobj2fid ko2iblnd-probe

CLEANFILES = $(genscripts)

$(genscripts): %: %.in
if BUILD_DLC
	sed -e 's,@sysconfdir\@,$(sysconfdir),g' \
	    -e 's,@scriptlibdir\@,$(scriptlibdir),g' \
	    -e 's,@BUILD_DLC_TRUE\@,,g' \
	    -e 's,@BUILD_DLC_FALSE\@,\#,g' $< > $@
else
	sed -e 's,@sysconfdir\@,$(sysconfdir),g' \
	    -e 's,@scriptlibdir\@,$(scriptlibdir),g' \
	    -e 's,@BUILD_DLC_TRUE\@,\#,g' \
	    -e 's,@BUILD_DLC_FALSE\@,,g' $< > $@
endif
	chmod +x $@
