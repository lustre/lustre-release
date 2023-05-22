# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# lnet/doc/Makefile.am
#
# Automake file for lnet man pages
#

MANFILES =					\
	lnetctl.8				\
	lst.8					\
	lnet.7

if MANPAGES
if UTILS
man_MANS = $(MANFILES)
endif
endif

CLEANFILES = *.aux *.tex *.log *.pdf

EXTRA_DIST = $(MANFILES)

all:
