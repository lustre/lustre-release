/*
 * TITLE(ppid_h, "@(#) $Id: ppid.h,v 1.1.6.1 2003/05/19 17:55:55 freym Exp $");
 */

#ifndef _INCppidh_
#define _INCppidh_

#include "defines.h"
// #include "idtypes.h"


#define MAX_PPID         1000    /* this needs to fit into 16 bits so the 
                                    maximum value is 65535. having it "large"
                                    can help w/ debugging process accounting
                                    but there are reasons for making it 
                                    somewhat smaller than the maximum --
                                    requiring storage for arrays that index 
                                    on the ppid, eg...  */
                                 
#define MAX_GID          1000    /* this needs to fit into 16 bits... */

#define MAX_FIXED_PPID   100
#define MAX_FIXED_GID    100
#define PPID_FLOATING    MAX_FIXED_PPID+1   /* Floating area starts here */
#define GID_FLOATING     MAX_FIXED_GID+1    /* Floating area starts here */
#define NUM_PTL_TASKS    MAX_FIXED_PPID+80  /* Maximum no. portals tasks */

#define PPID_AUTO        0

/* Minimum PPID is 1 */
#define PPID_BEBOPD      1            /* bebopd */
#define  GID_BEBOPD      1            /* bebopd */

#define PPID_PCT         2            /* pct */
#define  GID_PCT         2            /* pct */

#define PPID_FYOD        3            /* fyod */
#define  GID_FYOD        3            /* fyod */

#define PPID_GDBWRAP     11           /* portals proxy for gdb */
#define  GID_GDBWRAP     11           /* portals proxy for gdb */

#define PPID_TEST        15           /* for portals tests */
#define  GID_TEST        15

#define  GID_YOD         5            /* yod */
#define  GID_PINGD       6            /* pingd */
#define  GID_BT          7            /* bt */
#define  GID_PTLTEST     8            /* ptltest */
#define  GID_CGDB        9            /* cgdb */
#define  GID_TVDSVR     10            /* start-tvdsvr */

#endif /* _INCppidh_ */
