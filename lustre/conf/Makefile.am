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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2014, 2015, Intel Corporation.
#

#
# This file is part of Lustre, http://www.lustre.org/
#

SUBDIRS = resource
DIST_SUBDIRS = resource

EXTRA_DIST = lustre.dtd lustre2ldif.xsl top.ldif \
             99-lustre.rules lustre ldev.conf ko2iblnd.conf lsvcgss \
             lnet_routes.conf lnet.conf lgssc.conf 99-lustre-server.rules

sysconf_DATA = lnet.conf

if UTILS
noinst_DATA = top.ldif lustre2ldif.xsl
sysconf_DATA += lnet_routes.conf
endif

udevrulesdir = $(sysconfdir)/udev/rules.d
udevrules_DATA = 99-lustre.rules

if SERVER
udevrules_DATA += 99-lustre-server.rules
if ZFS_ENABLED
sysconf_DATA += ldev.conf
endif
if RHEL
sysconfigdir = $(sysconfdir)/sysconfig
sysconfig_DATA = lustre
if GSS_KEYRING
sysconfig_DATA += lsvcgss
endif
endif
endif
if GSS_KEYRING
requestkeydir = $(sysconfdir)/request-key.d
requestkey_DATA = lgssc.conf
endif

modprobedir = $(sysconfdir)/modprobe.d
modprobe_DATA = ko2iblnd.conf
