# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

MANFILES =					\
	lustre.7				\
	lnet.7


LIBMAN = 					\
	lustreapi.7				\
	llapi_layout.7

if MANPAGES
man_MANS = $(LIBMAN)
if UTILS
man_MANS += $(MANFILES)
endif
endif

CLEANFILES = *.aux *.tex *.log *.pdf
EXTRA_DIST = $(MANFILES) $(LIBMAN)

all:
