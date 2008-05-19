#define DEBUG_SUBSYSTEM S_RPC
#ifndef __KERNEL__
# include <liblustre.h>
#endif

#ifdef __KERNEL__
# ifndef AUTOCONF_INCLUDED
#  include <linux/config.h>
# endif
# ifdef CONFIG_FS_POSIX_ACL
#  include <linux/fs.h>
#  ifdef HAVE_XATTR_ACL
#   include <linux/xattr_acl.h>
#  else
#   define xattr_acl_entry  posix_acl_xattr_entry
#   define xattr_acl_header posix_acl_xattr_header
#  endif
#  ifdef HAVE_LINUX_POSIX_ACL_XATTR_H
#   include <linux/posix_acl_xattr.h>
#  endif
# endif
#endif

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_disk.h>

