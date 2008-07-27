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
# version 2 along with this program; If not, see [sun.com URL with a
# copy of GPLv2].
#
# Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
# CA 95054 USA or visit www.sun.com if you need additional information or
# have any questions.
#
# GPL HEADER END
#

#
# Copyright  2008 Sun Microsystems, Inc. All rights reserved
# Use is subject to license terms.
#

#
# This file is part of Lustre, http://www.lustre.org/
# Lustre is a trademark of Sun Microsystems, Inc.
#

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
