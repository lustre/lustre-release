# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

AUTOMAKE_OPTIONS = foreign

if LINUX25
DIRS24 = 
else
DIRS24 = ptlbd
endif

if LIBLUSTRE
SUBDIRS = portals obdclass lov ptlrpc obdecho  osc utils mdc lvfs #liblustre
else
SUBDIRS = lvfs portals obdclass include $(DIRS24) mds utils obdfilter mdc osc ost 
SUBDIRS+= llite obdecho lov cobd tests doc scripts conf ptlrpc
endif

if SNAPFS
SUBDIRS+= snapfs
endif

if SMFS 
SUBDIRS += smfs
endif
DIST_SUBDIRS = $(SUBDIRS) liblustre snapfs smfs
EXTRA_DIST = BUGS FDL Rules kernel_patches

# We get the version from the spec file.
CONFIGURE_DEPENDENCIES = scripts/lustre.spec.in

dist-hook:
	find $(distdir) -name .deps | xargs rm -rf
	find $(distdir) -name CVS | xargs rm -rf

include $(top_srcdir)/Rules

rpms: dist Makefile
	rpmbuild -ta $(distdir).tar.gz

CSTK=/tmp/checkstack
CSTKO=/tmp/checkstack.orig

checkstack:
	[ -f ${CSTK} -a ! -s ${CSTKO} ] && mv ${CSTK} ${CSTKO} || true
	for i in ${SUBDIRS} portals/knals/*; do				     \
		MOD=$$i/`basename $$i`.o;				     \
		[ -f $$MOD ] && objdump -d $$MOD | perl tests/checkstack.pl; \
	done | sort -nr > ${CSTK}
	[ -f ${CSTKO} ] && ! diff -u ${CSTKO} ${CSTK} || head -30 ${CSTK}

checkstack-update:
	[ -f ${CSTK} ] && mv ${CSTK} ${CSTKO}

checkstack-clean:
	rm -f ${CSTK} ${CSTKO}
