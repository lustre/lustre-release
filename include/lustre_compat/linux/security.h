/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __COMPAT_SECURITY_H
#define __COMPAT_SECURITY_H

#include <linux/security.h>

#ifdef CONFIG_SECURITY
int compat_security_file_alloc(struct file *file);
void compat_security_file_free(struct file *file);
#else
static inline int compat_security_file_alloc(struct file *file)
{
	return 0;
}
static inline void compat_security_file_free(struct file *file)
{
}
#endif

#endif /* __COMPAT_SECURITY_H */
