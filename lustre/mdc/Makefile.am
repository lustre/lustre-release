# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=

MODULE = mdc
modulefs_DATA = mdc.o
EXTRA_PROGRAMS = mdc

LINX= mds_updates.c ll_pack.c lov_pack.c client.c
mdc_SOURCES =  mdc_request.c mdc_reint.c $(LINX)

lov_pack.c: 
	test -e lov_pack.c || ln -sf $(top_srcdir)/lib/lov_pack.c .
ll_pack.c: 
	test -e ll_pack.c || ln -sf $(top_srcdir)/lib/ll_pack.c .
mds_updates.c: 
	test -e mds_updates.c || ln -sf $(top_srcdir)/lib/mds_updates.c .
client.c: 
	test -e client.c || ln -sf $(top_srcdir)/lib/client.c .


include $(top_srcdir)/Rules
