# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

# Every *.5 in this directory is shipped, and installed subject to the
# conditionals below.  Do not turn this back into a hand-written list of
# pages.
MANFILES = $(notdir $(wildcard $(srcdir)/*.5))

if MANPAGES
if UTILS
man5_MANS = $(MANFILES)
endif
endif

CLEANFILES = *.aux *.tex *.log *.pdf
EXTRA_DIST = $(MANFILES)

all:
