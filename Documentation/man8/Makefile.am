# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

MANFILES = 					\
	lnetctl.8				\
	lst.8

SERVER_MANFILES =				\
	lctl-nodemap-banlist-add.8		\
	lctl-nodemap_banlist_add.8		\
	lctl-nodemap-banlist-del.8		\
	lctl-nodemap_banlist_del.8		\
	lctl-nodemap-fileset-add.8		\
	lctl-nodemap_fileset_add.8		\
	lctl-nodemap-fileset-del.8		\
	lctl-nodemap_fileset_del.8		\
	lctl-nodemap-fileset-modify.8		\
	lctl-nodemap_fileset_modify.8

if MANPAGES
man_MANS =
if SERVER
man_MANS += $(SERVER_MANFILES)
endif

if UTILS
man_MANS += $(MANFILES)
endif
endif

CLEANFILES = *.aux *.tex *.log *.pdf
EXTRA_DIST = $(MANFILES) $(SERVER_MANFILES)

all:
