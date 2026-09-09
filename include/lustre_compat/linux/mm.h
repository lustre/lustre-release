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

#ifndef HAVE_IS_PCI_P2PDMA_PAGE
static inline bool is_pci_p2pdma_page(const struct page *page)
{
	return false;
}
#endif

#ifndef HAVE_PAGE_PGMAP
#define page_pgmap(page) ((page)->pgmap)
#endif

#endif /* _LINUX_MM_LUSTRE_H */
