# Copyright (C) 2001, 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution


MODULE = libcfs
modulenet_DATA = libcfs.o
EXTRA_PROGRAMS = libcfs

DISTCLEANFILES = *.orig *.rej

DEFS =
libcfs_SOURCES = module.c proc.c debug.c lwt.c

# Don't distribute any patched files.
dist-hook:
	list='$(EXT2C)'; for f in $$list; do rm -f $(distdir)/$$f; done

include ../Rules.linux
