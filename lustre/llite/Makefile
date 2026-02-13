# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += lustre.o
lustre-objs := dcache.o dir.o file.o llite_lib.o llite_nfs.o
lustre-objs += rw.o lproc_llite.o namei.o symlink.o llite_mmap.o
lustre-objs += xattr.o xattr_cache.o
lustre-objs += rw26.o super25.o statahead.o xattr_security.o
lustre-objs += glimpse.o
lustre-objs += lcommon_cl.o
lustre-objs += lcommon_misc.o
lustre-objs += vvp_dev.o vvp_page.o vvp_io.o vvp_object.o
lustre-objs += pcc.o crypto.o
lustre-objs += llite_foreign.o llite_foreign_symlink.o

lustre-$(CONFIG_FS_POSIX_ACL) += acl.o
lustre-objs += $(lustre-y)
