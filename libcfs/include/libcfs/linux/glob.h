/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_GLOB_H
#define _LINUX_GLOB_H

#ifndef HAVE_GLOB

#include <linux/types.h>	/* For bool */
#include <linux/compiler.h>	/* For __pure */

bool __pure glob_match(char const *pat, char const *str);
#endif /* !HAVE_GLOB */

#endif	/* _LINUX_GLOB_H */
