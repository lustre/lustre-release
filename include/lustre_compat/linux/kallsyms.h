/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LINUX_KALLSYMS_LUSTRE_H
#define _LINUX_KALLSYMS_LUSTRE_H

#include_next <linux/kallsyms.h>

/* TODO: This will soon be private... */
void *cfs_kallsyms_lookup_name(const char *name);
int lustre_symbols_init(void);

#endif /*  _LINUX_KALLSYMS_LUSTRE_H */
