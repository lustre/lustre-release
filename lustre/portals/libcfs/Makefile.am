# Copyright (C) 2001, 2002 Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution


MODULE = portals
modulenet_DATA = portals.o
EXTRA_PROGRAMS = portals

LIBLINKS := lib-dispatch.c lib-eq.c lib-init.c lib-md.c lib-me.c lib-move.c lib-msg.c lib-ni.c lib-pid.c
APILINKS := api-eq.c api-errno.c api-init.c api-me.c api-ni.c api-wrap.c
LINKS = $(APILINKS) $(LIBLINKS) 
DISTCLEANFILES = $(LINKS) link-stamp *.orig *.rej

$(LINKS): link-stamp
link-stamp:
	-list='$(LIBLINKS)'; for f in $$list; do echo $$f ; ln -sf $(srcdir)/../portals/$$f .; done
	-list='$(APILINKS)'; for f in $$list; do echo $$f ; ln -sf $(srcdir)/../portals/$$f .; done
	echo timestamp > link-stamp

DEFS =
portals_SOURCES = $(LINKS) module.c proc.c debug.c

# Don't distribute any patched files.
dist-hook:
	list='$(EXT2C)'; for f in $$list; do rm -f $(distdir)/$$f; done

include ../Rules.linux
