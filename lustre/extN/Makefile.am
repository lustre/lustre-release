# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS:=-DEXPORT_SYMTAB
MODULE = extN
modulefs_DATA = extN.o
EXTRA_PROGRAMS = extN

EXTNP = htree-ext3-2.4.18.diff linux-2.4.18ea-0.8.26.diff
EXTNP+= ext3-2.4.18-ino_sb_macro.diff extN-misc-fixup.diff
EXTNC = balloc.c bitmap.c dir.c file.c fsync.c ialloc.c inode.c ioctl.c
EXTNC+= namei.c super.c symlink.c
EXTNI = extN_fs.h extN_fs_i.h extN_fs_sb.h extN_jbd.h
EXTN_EXTRA = include/linux/xattr.h include/linux/extN_xattr.h fs/extN/xattr.c
extN_SOURCES = $(EXTNC) $(EXTNI) xattr.c # punch.c
extN_DEPENDENCIES = patch-stamp
EXTRA_DIST = $(EXTNP) extN-2.4.18-ino_sb_fixup.diff extN-2.4.18-exports.diff
DISTCLEANFILES = $(EXTNC) $(EXTNI) patch-stamp *.orig *.rej
SUB=-e "s/ext3/extN/g" -e "s/EXT3/EXTN/g"

include $(top_srcdir)/Rules

# Patch the kernel files with our ext3 patches.  We need to go through some
# extra hoops because the include files are in a different tree and because
# patch likes to make local copies of files with (sym)links when it is patching
# them.  To avoid this, we copy/patch in the source dir instead of the build
# dir (if they are different).
patch-stamp: $(EXTNP)
	test -e $(top_srcdir)/fs || ln -sf . $(top_srcdir)/fs
	set -vx;\
	list='$(EXTN_EXTRA)'; for f in $$list; do $(RM) $(top_srcdir)/$$f; done
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
	(cd $(top_srcdir); patch -p1) < $(srcdir)/extN-2.4.18-ino_sb_fixup.diff
	-(cd $(top_srcdir); patch -p1) < $(srcdir)/extN-2.4.18-exports.diff
	echo timestamp > patch-stamp

$(EXTNC) $(EXTNI): patch-stamp

# Don't distribute any patched files.
dist-hook:
	rm -f $(top_srcdir)/fs
	list='$(EXTNC)'; for f in $$list; do rm -f $(distdir)/$$f; done
	list='$(EXTNI)'; for i in $$list; do                                  \
		rm -f $(distdir)/../include/linux/$$i;                        \
	done
