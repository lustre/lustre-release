# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

AUTOMAKE_OPTIONS = foreign

DIST_SUBDIRS = 
SUBDIRS = include portals conf scripts ldlm

# ldiskfs creates headers that the ldiskfs fsfilt will need
if MODULES
if LDISKFS
SUBDIRS += ldiskfs
else
DIST_SUBDIRS += ldiskfs
endif
else
DIST_SUBDIRS += ldiskfs
endif

# directories shared by the liblustre and modules builds
CORE_SUBDIRS = lvfs obdclass lov ptlrpc obdecho osc mdc
if LIBLUSTRE
SUBDIRS += $(CORE_SUBDIRS)
else
if MODULES
SUBDIRS += $(CORE_SUBDIRS)
else
DIST_SUBDIRS += $(CORE_SUBDIRS)
endif
endif

# directories only built in the modules build
MODULES_SUBDIRS = mds obdfilter ost llite cobd
MODULES_DIST_SUBDIRS =

if LINUX25
MODULES_DIST_SUBDIRS += ptlbd
else
MODULES_SUBDIRS += ptlbd
endif

if SNAPFS
MODULES_SUBDIRS += snapfs
else
MODULES_DIST_SUBDIRS += snapfs
endif

if SMFS
MODULES_SUBDIRS += smfs
else
MODULES_DIST_SUBDIRS += smfs
endif

if MODULES
SUBDIRS += $(MODULES_SUBDIRS)
DIST_SUBDIRS += $(MODULES_DIST_SUBDIRS)
else
DIST_SUBDIRS += $(MODULES_SUBDIRS) $(MODULES_DIST_SUBDIRS)
endif

if LIBLUSTRE
SUBDIRS += liblustre
else
DIST_SUBDIRS += liblustre
endif

if DOC
SUBDIRS += doc
else
DIST_SUBDIRS += doc
endif

if UTILS
SUBDIRS += utils
else
DIST_SUBDIRS += utils
endif

if TESTS
SUBDIRS += tests
else
DIST_SUBDIRS += tests
endif

DIST_SUBDIRS += $(SUBDIRS)

EXTRA_DIST = BUGS FDL Rules.in kernel_patches kernel-tests/Makefile

dist-hook:
	find $(distdir) -name .deps | xargs rm -rf
	find $(distdir) -name CVS | xargs rm -rf

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
