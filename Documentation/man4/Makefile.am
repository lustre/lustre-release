# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

# Every *.4 in this directory is shipped, and installed subject to the
# conditional below.  Do not turn this back into a hand-written list of pages.
MANFILES = $(notdir $(wildcard $(srcdir)/*.4))

if MANPAGES
if SERVER
man4_MANS = $(MANFILES)
else
# Server-specific pages, which ship even without the utilities.  This is a
# classification, not the packaging list: a page left out of it still
# installs and ships, but it is also included in the client parameters set.
SERVER_MANFILES =				\
	expected_clients.4			\
	lod.%					\
	mdd.%					\
	mdt.%					\
	mgs.%					\
	nodemap.%				\
	obdfilter.%				\
	osd-%					\
	ost.%

man4_MANS = $(filter-out $(SERVER_MANFILES),$(MANFILES))
endif # SERVER
endif # MANPAGES

CLEANFILES = *.aux *.tex *.log *.pdf
EXTRA_DIST = $(MANFILES)

all:
