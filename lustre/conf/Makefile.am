# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

EXTRA_DIST = lustre.dtd lustre.schema slapd-lustre.conf lustre2ldif.xsl top.ldif
ldapconfdir = $(sysconfdir)/openldap
ldapschemadir = $(sysconfdir)/openldap/schema
ldapconf_SCRIPTS = slapd-lustre.conf
ldapschema_SCRIPTS = lustre.schema
pkglibdir = '${exec_prefix}/usr/lib/$(PACKAGE)'
pkglib_DATA = top.ldif lustre2ldif.xsl

include $(top_srcdir)/Rules

