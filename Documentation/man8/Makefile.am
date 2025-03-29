# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

MANFILES = 					\
	lnetctl.8				\
	lst.8

if MANPAGES
if UTILS
man_MANS = $(MANFILES)
endif
endif

CLEANFILES = *.aux *.tex *.log *.pdf
EXTRA_DIST = $(MANFILES)

all:
