# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

# Every *.7 in this directory is shipped, and installed subject to the
# conditionals below.  Do not turn this back into a hand-written list of
# pages.
MANFILES = $(notdir $(wildcard $(srcdir)/*.7))

# API overview pages, which ship even without the utilities.  This is a
# classification, not the packaging list: a page left out of it still
# installs and ships, but it is only included in the utilities set.
LIBMAN = 					\
	lustreapi.7				\
	llapi_layout.7

if MANPAGES
if UTILS
man7_MANS = $(MANFILES)
else
man7_MANS = $(LIBMAN)
endif # UTILS
endif # MANPAGES

CLEANFILES = *.aux *.tex *.log *.pdf
EXTRA_DIST = $(MANFILES)

all:
