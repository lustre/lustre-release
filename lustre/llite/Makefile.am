# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS= 

MODULE = llite
modulefs_DATA = llite.o
EXTRA_PROGRAMS = llite

page.c: 
	test -e page.c || ln -sf $(top_srcdir)/lib/page.c


LINX=page.c
llite_SOURCES = dcache.c commit_callback.c super.c rw.c
llite_SOURCES += file.c dir.c sysctl.c namei.c symlink.c $(LINX)
llite_SOURCES += lov_pack.c

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

lov_pack.c: 
	test -e lov_pack.c || ln -sf $(top_srcdir)/lib/lov_pack.c .

include $(top_srcdir)/Rules
