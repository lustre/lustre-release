/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef _LINUX_MM_LUSTRE_H
#define _LINUX_MM_LUSTRE_H

#include <linux/mm.h>

unsigned long compat_totalram_pages(void);
#ifndef COMPAT_BUILD
#define totalram_pages()	compat_totalram_pages()
#endif

#if defined(HAVE_ACCOUNT_PAGE_DIRTIED) && \
    !defined(HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT)
unsigned int compat_account_page_dirtied(struct page *page,
					 struct address_space *mapping);
#ifndef COMPAT_BUILD
#define account_page_dirtied	compat_account_page_dirtied
#endif
#endif

#endif /* _LINUX_MM_LUSTRE_H */
