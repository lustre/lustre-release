/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * Lustre wire protocol definitions.
 *
 * All structs passing over the wire should be declared here (lov_mds_md
 * being the lone exception).  Structs must be properly aligned to put
 * 64-bit values on an 8-byte boundary.  Any structs being added here
 * must also be added to utils/wirecheck.c and "make newwiretest" run
 * to regenerate the utils/wiretest.c sources.  This allows us to verify
 * that wire structs have the proper alignment/size on all architectures.
 *
 * We assume all nodes are either little-endian or big-endian, and we
 * always send messages in the sender's native format.  The receiver
 * detects the message format by checking the 'magic' field of the message
 * (see lustre_msg_swabbed() below).
 *
 * Each wire type has corresponding 'lustre_swab_xxxtypexxx()' routines,
 * implemented either here, inline (trivial implementations) or in
 * ptlrpc/pack_generic.c.  These 'swabbers' convert the type from "other"
 * endian, in-place in the message buffer.
 *
 * A swabber takes a single pointer argument.  The caller must already have
 * verified that the length of the message buffer >= sizeof (type).
 *
 * For variable length types, a second 'lustre_swab_v_xxxtypexxx()' routine
 * may be defined that swabs just the variable part, after the caller has
 * verified that the message buffer is large enough.
 */

#ifndef _LINUX_LUSTRE_IDL_H_
#define _LINUX_LUSTRE_IDL_H_

#ifndef _LUSTRE_IDL_H_
#error Do not #include this file directly. #include <lustre_idl.h> instead
#endif

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#else
#include <lustre/types.h>
#endif

#ifdef __KERNEL__
# include <linux/types.h>
# include <linux/fs.h>    /* to check for FMODE_EXEC, dev_t, lest we redefine */
#else
#ifdef __CYGWIN__
# include <sys/types.h>
#elif defined(_AIX)
# include <inttypes.h>
#else
# include <stdint.h>
#endif
#endif

#endif
