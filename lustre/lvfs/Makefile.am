# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
DEFS= 

if LIBLUSTRE
noinst_LIBRARIES = liblvfs.a
liblvfs_a_SOURCES = lvfs_userfs.c
liblvfs_a_CFLAGS = -fPIC

#if MYSQL
#liblvfs_a_SOURCES += lvfs_user_mysql.c
#endif

else

MODULE = lvfs

if EXTN
FSMOD = fsfilt_extN
else
FSMOD = fsfilt_ext3
endif

modulefs_DATA = lvfs.o $(FSMOD).o

EXTRA_PROGRAMS = lvfs $(FSMOD)
lvfs_SOURCES = lvfs_common.c lvfs_linux.c fsfilt.c lvfs_internal.h
if EXTN
fsfilt_extN_SOURCES = fsfilt_extN.c lvfs_internal.h
else
fsfilt_ext3_SOURCES = fsfilt_ext3.c lvfs_internal.h
endif
endif

include $(top_srcdir)/Rules

if LINUX25
# workaround for fsfilt_ext3
$(FSMOD).o: $(FSMOD).c
	$(COMPILE) -UKBUILD_MODNAME -DKBUILD_MODNAME=$(FSMOD) -c -o $(FSMOD)_tmp.o $<
	rm -f $(FSMOD)_tmp.c
	$(LINUX)/scripts/modpost $(LINUX)/vmlinux $(FSMOD)_tmp.o
	$(COMPILE) -UKBUILD_MODNAME -UKBUILD_BASENAME -DKBUILD_BASENAME=$(FSMOD) \
		-c $(FSMOD)_tmp.mod.c
	$(LD) -m "`$(LD) --help | awk '/supported emulations/ {print $$4}'`" -r \
		-o $(FSMOD).o $(FSMOD)_tmp.o $(FSMOD)_tmp.mod.o
endif
