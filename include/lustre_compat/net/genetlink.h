/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_NET_GENETLINK_H__
#define __LIBCFS_NET_GENETLINK_H__

#include <linux/netdevice.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#ifndef HAVE_NLA_STRDUP
char *nla_strdup(const struct nlattr *nla, gfp_t flags);
#endif /* !HAVE_NLA_STRDUP */

#ifdef HAVE_NLA_STRLCPY
#define nla_strscpy	nla_strlcpy
#endif /* HAVE_NLA_STRLCPY */

#ifdef HAVE_GENL_DUMPIT_INFO
struct compat_genl_info {
	const struct genl_family *family;
};

static inline const struct compat_genl_info *
compat_genl_info_dump(struct netlink_callback *cb)
{
	const struct genl_dumpit_info *dgi = genl_dumpit_info(cb);
	struct compat_genl_info *info;

	info = (struct compat_genl_info *)cb->args[1];
	info->family = dgi->family;

	return info;
}
#else

#define compat_genl_info	genl_info
#define compat_genl_info_dump	genl_info_dump

#endif /* HAVE_GENL_DUMPIT_INFO */

#endif /* __LIBCFS_NET_GENETLINK_H__ */
