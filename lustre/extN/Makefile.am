# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

DEFS=-DEXPORT_SYMTAB
MODULE = extN
modulefs_DATA = extN.o
EXTRA_PROGRAMS = extN

# NOTE: If you are not using a RedHat 12.5 or later kernel, then you need to
#       apply the "fixes" patch first, as it fixes a number of bugs in ext3.
#       It will be applied automatically by the extN build process, or you
#       can apply it to the source kernel tree and fix ext3 also.  For chaos22
#       (or other RH < 12.5 kernels) use the "chaos22" patch instead.
EXTN_FIXES = patch-2.4.18-chaos22
#EXTN_FIXES = ext3-2.4.18-fixes.diff
EXTNP = htree-ext3-2.4.18.diff linux-2.4.18ea-0.8.26.diff
EXTNP+= ext3-2.4.18-ino_sb_macro.diff extN-misc-fixup.diff
EXTNC = balloc.c bitmap.c dir.c file.c fsync.c ialloc.c inode.c ioctl.c
EXTNC+= namei.c super.c symlink.c
EXTNI = extN_fs.h extN_fs_i.h extN_fs_sb.h extN_jbd.h quotaops.h
EXTN_EXTRA = include/linux/xattr.h include/linux/extN_xattr.h fs/extN/xattr.c
EXTN_EXTRA += include/linux/quotaops.h
extN_SOURCES = $(EXTNC) xattr.c # punch.c
extN_DEPENDENCIES = patch-stamp
EXTRA_DIST = $(EXTNP) $(EXTN_FIXES) \
	extN-2.4.18-ino_sb_fixup.diff extN-2.4.18-exports.diff \
	$(wildcard extN.patch-*)
DISTCLEANFILES = -r $(extN_SOURCES) sed-stamp patch-stamp *.orig *.rej
SUB=-e "s/ext3/extN/g" -e "s/EXT3/EXTN/g" -e "s/extern __inline__/static inline/"

distclean:
	cd .. && rm -f $(EXTN_EXTRA)

include $(top_srcdir)/Rules

# Following 2 vars are for buildind outside the source tree.
extN_orig = $(top_builddir)/$(subdir)/extN.orig
extN_include_orig = $(top_builddir)/$(subdir)/extN-include.orig

# Create a fresh extN patch.
# This is for when the patch-stamp target fails for your kernel.
# Just edit the files until you like them, then do `make diff', and
# it will create a specialized patch for your particular kernel.
# Check it in, and the build should work for you without disrupting
# the other developers.
# Of course, the ideal is to merge changes so that the default patch
# set works for nearly everybody.  This is mainly for damage control.

diff:
	$(RM) extN.patchT
	l='$(EXTNC)'; for f in $$l; do                                        \
          echo "$$f";                                                         \
          (diff -u $(extN_orig)/$$f extN/$$f) >> extN.patchT;              \
          test $$? -le 1 || exit 1;                                       
	done
	l='$(EXTNI)'; for f in $$l; do                                        \
          echo "$$f";                                                         \
          (diff -u $(extN_include_orig)/$$f $(top_srcdir)/include/linux/$$f)>>extN.patchT;\
          test $$? -le 1 || exit 1;                                          
	done
	l='$(EXTN_EXTRA)'; for f in $$l; do                                   \
          f=`echo "$$f" | sed 's%^fs/%%'`;                                    \
          echo "$$f";                                                         \
          (cd $(top_srcdir) &&                                                \
            diff -u /dev/null $$f) >> extN.patchT;                            \
          test $$? -le 1 || exit 1;                                          
	done
	mv -f extN.patchT $(top_builddir)/$(subdir)/extN.patch-$(RELEASE)
	echo "Don't forget to add $(srcdir)/extN.patch-$(RELEASE) to CVS!"



.PHONY: diff

# Just do the SUB transformation on all our source files.


sed-stamp:
	$(RM) $@
	rm -rf $(extN_orig) $(extN_include_orig)
	mkdir $(extN_orig) $(extN_include_orig)
	list='$(EXTNC)'; for f in $$list; do                                  \
          echo "creating $(extN_orig)/$$f";				\
          sed $(SUB) $(LINUX)/fs/ext3/$$f > $(extN_orig)/$$f; \
        done
	list='$(EXTNI)'; for i in $$list; do                                  \
          s=`echo $$i | sed "s/extN/ext3/"`;                                  \
          echo "creating $(extN_include_orig)/$$i"; \
          sed $(SUB) $(LINUX)/include/linux/$$s > $(extN_include_orig)/$$i; \
        done
	echo timestamp > $@


# Patch the kernel files with our ext3 patches.  We need to go through some
# extra hoops because the include files are in a different tree and because
# patch likes to make local copies of files with (sym)links when it is patching
# them.  To avoid this, we copy/patch in the source dir instead of the build
# dir (if they are different).
# We also want to preserve the pristine transformed files for the diff target.



patch-stamp: sed-stamp $(EXTNP)
	test -e $(top_builddir)/include/linux || mkdir -p $(top_builddir)/include/linux	
	cp -a $(extN_orig)/* $(top_builddir)/$(subdir)
	cp -a $(extN_include_orig)/* $(top_builddir)/include/linux
	test -e $(top_builddir)/fs || ln -s . $(top_builddir)/fs
	list='$(EXTN_EXTRA)'; for f in $$list; do $(RM) $(top_builddir)/$$f; done
	if [ -f $(srcdir)/extN.patch-$(RELEASE) ]; then                       \
	  echo "applying patch $(srcdir)/extN.patch-$(RELEASE)";              \
	  (cd $(top_builddir) && patch -p0) < $(srcdir)/extN.patch-$(RELEASE);  \
	else                                                                  \
	  echo "If first patch fails, read NOTE in extN/Makefile.am";         \
	  list='$(EXTNP)'; \
	  sed '/i_version/q' $(extN_orig)/namei.c | tail -2 |          \
	    grep extN_mark_inode_dirty >/dev/null && list="$(EXTN_FIXES) $$list"; \
	  for p in $$list; do                                                 \
	    echo "applying patch $$p";                                        \
	    sed $(SUB) $(srcdir)/$$p |                                        \
	      (cd $(top_builddir) && patch -p1) || exit $$?;                    \
	  done;                                                               \
	  echo "It is OK if the next patch says it is already applied";       \
	  echo "applying patch $(srcdir)/extN-2.4.18-exports.diff";           \
	  (cd $(top_builddir) &&                                              \
	    patch -N -p1) < $(srcdir)/extN-2.4.18-exports.diff;               \
	  echo "applying patch $(srcdir)/extN-2.4.18-ino_sb_fix.diff";        \
	  (cd $(top_builddir) &&                                              \
	    patch -p1) < $(srcdir)/extN-2.4.18-ino_sb_fixup.diff || exit $$?; \
	fi
	echo timestamp > $@




$(extN_SOURCES) $(EXTNI) $(EXTN_EXTRA): patch-stamp

# Don't distribute any patched files.
dist-hook:
	$(RM) $(top_srcdir)/fs
	list='$(EXTNC)'; for f in $$list; do $(RM) $(distdir)/$$f; done
	list='$(EXTNI)'; for i in $$list; do                                  \
	  $(RM) $(distdir)/../include/linux/$$i;                              \
	done
	list='$(EXTN_EXTRA)'; for f in $$list; do $(RM) $(distdir)/../$$f; done
