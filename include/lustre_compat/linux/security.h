/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __COMPAT_SECURITY_H
#define __COMPAT_SECURITY_H

#include <linux/security.h>

#ifdef CONFIG_SECURITY
int compat_security_file_alloc(struct file *file);
void compat_security_file_free(struct file *file);

#ifndef COMPAT_BUILD
#define security_file_alloc(file)	compat_security_file_alloc(file)
#define security_file_free(file)	compat_security_file_free(file)
#endif

#endif

#endif /* __COMPAT_SECURITY_H */
