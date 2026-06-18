/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Compiler context (lock) analysis annotations.
 *
 * Linux v7.0 added <linux/compiler-context-analysis.h>, which the
 * compiler can enforce with -Wthread-safety-analysis. The shared
 * (read-side) variants of the annotations have no sparse-era
 * equivalent, so define them away on older kernels.
 */

#ifndef _LUSTRE_COMPAT_LINUX_COMPILER_CONTEXT_ANALYSIS_H
#define _LUSTRE_COMPAT_LINUX_COMPILER_CONTEXT_ANALYSIS_H

#include <linux/compiler_types.h>

#ifndef __must_hold_shared
#define __must_hold_shared(...)
#endif

#ifndef __acquires_shared
#define __acquires_shared(...)
#endif

#ifndef __releases_shared
#define __releases_shared(...)
#endif

#ifndef __acquire_shared
#define __acquire_shared(x)	do { } while (0)
#endif

#ifndef __release_shared
#define __release_shared(x)	do { } while (0)
#endif

#endif /* _LUSTRE_COMPAT_LINUX_COMPILER_CONTEXT_ANALYSIS_H */
