# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:= 

MODULE = llite
modulefs_DATA = llite.o
EXTRA_PROGRAMS = llite

page.c: 
	test -e page.c || ln -sf $(top_srcdir)/lib/page.c


LINX=page.c
llite_SOURCES =  commit_callback.c page.c super.c rw.c file.c dir.c sysctl.c namei.c symlink.c

dist-hook:
	list='$(LINX)'; for f in $$list; do rm -f $(distdir)/$$f; done

include $(top_srcdir)/Rules
