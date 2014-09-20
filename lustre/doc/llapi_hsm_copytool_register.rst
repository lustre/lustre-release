===========================
llapi_hsm_copytool_register
===========================

------------------------------
Lustre API copytool management
------------------------------

:Author: Frank Zago
:Date:   2014-09-24
:Manual section: 3
:Manual group: Lustre HSM User API


SYNOPSIS
========

**#include <lustre/lustreapi.h>**

**int llapi_hsm_copytool_register(struct hsm_copytool_private \*\***\ priv\ **,
const char \***\ mnt\ **, int** archive_count\ **, int \***\ archives\ **,
int** rfd_flags\ **)**

**int llapi_hsm_copytool_unregister(struct hsm_copytool_private \*\***\ priv
**)**

**int llapi_hsm_copytool_get_fd(struct hsm_copytool_private \***\ ct\ **)**

**int llapi_hsm_copytool_recv(struct hsm_copytool_private \***\ priv\ **,
**struct hsm_action_list \*\***\ hal\ **, int \***\ msgsize\ **)**

**struct hsm_action_item \*hai_first(struct hsm_action_list \***\ hal\ **)**

**struct hsm_action_item \*hai_next(struct hsm_action_item \***\ hai\ **)**


DESCRIPTION
===========

To receive HSM requests from a Lustre filesystem, a copytool
application must register with Lustre by calling
**llapi_hsm_copytool_register**\ (). The mountpoint of the Lustre
filesystem to monitor is indicated by *mnt*. *archives* is an array
with up to 32 elements indicating which archive IDs to register
for. Each element is a number from 1 to 32. *archive_count* is the
number of valid elements in the *archive* array. If an element in
*archives* is 0, or if *archive_count* is 0, then all archives will be
monitored. *rfd_flags* determines whether **llapi_hsm_copytool_recv**
will be blocking, with 0, or non-blocking, with O_NONBLOCK.

**llapi_hsm_copytool_register** returns *priv*, an opaque
pointer that must be used with the other functions.

**llapi_hsm_copytool_unregister** unregisters a copytool. *priv* is
the opaque handle returned by **llapi_hsm_copytool_register**.

**llapi_hsm_copytool_get_fd** returns the file descriptor used by the
library to communicate with the kernel. This descriptor is only
intended to be used with **select(2)** or **poll(2)**. *rfd_flags*
should have been set to O_NONBLOCK.

To receive the requests, the application has to call
**llapi_hsm_copytool_recv**. When it returns 0, a message is available
in *hal*, and its size in bytes is returned in *msgsize*. *hal* points
to a buffer allocated by the Lustre library. It contains one or more
HSM requests. This buffer is valid until the next call to
**llapi_hsm_copytool_recv**.

*hal* is composed of a header of type *struct hsm_action_list*
followed by one or several HSM requests of type *struct
hsm_action_item*::

    struct hsm_action_list {
       __u32 hal_version;
       __u32 hal_count;         /* number of hai's to follow */
       __u64 hal_compound_id;   /* returned by coordinator */
       __u64 hal_flags;
       __u32 hal_archive_id;    /* which archive backend */
       __u32 padding1;
       char hal_fsname[0];      /* null-terminated name of filesystem */
    };

    struct hsm_action_item {
        __u32      hai_len;     /* valid size of this struct */
        __u32      hai_action;  /* hsm_copytool_action, but use known size */
        lustre_fid hai_fid;     /* Lustre FID to operated on */
        lustre_fid hai_dfid;    /* fid used for data access */
        struct hsm_extent hai_extent;  /* byte range to operate on */
        __u64      hai_cookie;  /* action cookie from coordinator */
        __u64      hai_gid;     /* grouplock id */
        char       hai_data[0]; /* variable length */
    };

To iterate through the requests, use **hai_first** to get the first
request, then **hai_next**.


RETURN VALUE
============

**llapi_hsm_copytool_register** and **llapi_hsm_copytool_unregister**
return 0 on success. On error, a negative errno is returned.

**llapi_hsm_copytool_get_fd** returns the file descriptor associated
 with the register copytool. On error, a negative errno is returned.

**llapi_hsm_copytool_recv** returns 0 when a message is available. If
the copytool was set to non-blocking operation, -EWOULDBLOCK is
immediately returned if no message is available. On error, a negative
errno is returned.


ERRORS
======

**-EINVAL** An invalid value was passed, the copytool is not
   registered, ...

**-ESHUTDOWN** The transport endpoint shutdown.

**-EPROTO** Lustre protocol error.

**-EWOULDBLOCK** No HSM message is available, and the copytool was set
to not block on receives.


SEE ALSO
========

**llapi_hsm_action_begin**\ (3), **llapi_hsm_action_end**\ (3),
**llapi_hsm_action_progress**\ (3), **llapi_hsm_action_get_dfid**\ (3),
**llapi_hsm_action_get_fd**\ (3), **lustreapi**\ (7)

See *lhsmtool_posix.c* in the Lustre sources for a use case of this
API.
