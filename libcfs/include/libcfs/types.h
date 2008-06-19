#ifndef _LIBCFS_TYPES_H
#define _LIBCFS_TYPES_H

/*
 * This file was inttroduced to resolve XT3 (Catamount) build issues.
 * The orignal idea was to move <lustre/types.h> here however at
 * the time of this writing
 * it's unclear what external dependencies are tied
 * to that file (It's not just some source file #including it)
 * there is some build/packaging infrastructure that includes it.
 * Hopefully that will be resolved shortly, that file will
 * be removed, its contents copied here and this comment can be deleted.
 */

#include <lustre/types.h>

#endif
