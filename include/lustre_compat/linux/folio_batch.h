/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2025 Hewlett Packard Enterprise Development LP.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */
#ifndef _LUSTRE_COMPAT_FOLIO_BATCH_H
#define _LUSTRE_COMPAT_FOLIO_BATCH_H

#if __has_include(<linux/folio_batch.h>)
# include <linux/folio_batch.h>
#else
# include <linux/pagevec.h>
#endif

#ifndef FOLIO_BATCH_SIZE
#define FOLIO_BATCH_SIZE	PAGEVEC_SIZE
#endif

#endif /* _LUSTRE_COMPAT_FOLIO_BATCH_H */
