# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:=-DEXPORT_SYMTAB
MODULE = extN
modulefs_DATA = extN.o
EXTRA_PROGRAMS = extN

EXTNP = htree-ext3-2.4.18.diff ext3-ino_sb-macro.diff
EXTNC = balloc.c bitmap.c dir.c file.c fsync.c ialloc.c inode.c ioctl.c
EXTNC+= namei.c super.c symlink.c
EXTNI = extN_fs.h extN_fs_i.h extN_fs_sb.h extN_jbd.h
extN_SOURCES = $(EXTNC) $(EXTNI) page.c # punch.c
EXTRA_DIST = $(EXTNP)
DISTCLEANFILES = $(EXTNC) $(EXTNI) patch-stamp *.orig *.rej
SUB=-e "s/ext3/extN/g" -e "s/EXT3/EXTN/g"

include $(top_srcdir)/Rules

page.c:
	test -e page.c || ln -sf $(top_srcdir)/lib/page.c

# Patch the kernel files with our ext3 patches.  We need to go through some
# extra hoops because the include files are in a different tree and because
# patch likes to make local copies of files with (sym)links when it is patching
# them.  To avoid this, we copy/patch in the source dir instead of the build
# dir (if they are different).
$(EXTNC) $(EXTNI): patch-stamp
patch-stamp:
	test -e $(top_srcdir)/fs || ln -sf . $(top_srcdir)/fs
	set -vx;\
	list='$(EXTNC)'; for f in $$list; do                                  \
	sed $(SUB) $(LINUX)/fs/ext3/$$f > $(top_srcdir)/fs/extN/$$f;          \
	done
	set -vx;\
	list='$(EXTNI)'; for i in $$list; do                                  \
	s=`echo $$i | sed "s/extN/ext3/"`;                                    \
	sed $(SUB) $(LINUX)/include/linux/$$s >                               \
		$(top_srcdir)/include/linux/$$i;                              \
	done
	set -vx;\
	list='$(EXTNP)'; for p in $$list; do                                  \
	sed $(SUB) $(srcdir)/$$p | (cd $(top_srcdir); patch -p1);             \
	done
	(cd $(top_srcdir); patch -p1) < $(srcdir)/extN-ino_sb-fixup.diff
	echo timestamp > patch-stamp

# Don't distribute any patched files.
dist-hook:
	rm -f $(top_srcdir)/fs
	list='$(EXTNC)'; for f in $$list; do rm -f $(distdir)/$$f; done
	list='$(EXTNI)'; for i in $$list; do                                  \
		rm -f $(distdir)/../include/linux/$$i;                        \
	done
