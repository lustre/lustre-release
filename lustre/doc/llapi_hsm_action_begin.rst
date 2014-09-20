======================
llapi_hsm_action_begin
======================

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

**int llapi_hsm_action_begin(struct hsm_copyaction_private \*\***\ phcp\ **,
const struct hsm_copytool_private \***\ ct\ **, const struct
hsm_action_item \***\ hai\ **, int** restore_mdt_index\ **, int**
restore_open_flags\ **, bool** is_error\ **)**

**int llapi_hsm_action_end(struct hsm_copyaction_private \*\***\ phcp\ **,
const struct hsm_extent \***\ he\ **, int** hp_flags\ **, int** errval\ **)**

**int llapi_hsm_action_progress(struct hsm_copyaction_private \***\ hcp\ **,
const struct hsm_extent \***\ he\ **, __u64** total\ **, int** hp_flags\ **)**

**int llapi_hsm_action_get_dfid(const struct hsm_copyaction_private \***\ hcp\ **,
lustre_fid  \***\ fid\ **)**

**int llapi_hsm_action_get_fd(const struct hsm_copyaction_private \***\ hcp\ **)**


DESCRIPTION
===========

When a copytool is ready to process an HSM action received through
**llapi_hsm_copytool_recv**\ (), it must first call
**llapi_hsm_action_begin**\ () to initialize the internal action
state, stored in *phcp*. *ct* is the opaque copytools handle
previously returned by **llapi_hsm_copytool_register**\ (). *hai* is
the request. *restore_mdt_index* and *restore_open_flags* are only
used for an **HSMA_RESTORE** type of request. *restore_mdt_index* is
the MDT index on which to create the restored file, or -1 for
default. If the copytool does not intend to process the request, it
should set *is_error* to **true**, and then call
**llapi_hsm_action_end**\ ().

While performing a copy (i.e. the HSM request is either
**HSMA_ARCHIVE** or **HSMA_RESTORE**), the copytool can inform Lustre
of the progress of the operation with **llapi_hsm_action_progress**\
(). *he* is the interval (*offset*, *length*) of the data copied. Each
interval must be unique; i.e. there must not be any overlap. *length*
is the total length that is expected to be transfered. *hp_flags*
should be 0. The progress can be checked on any Lustre client by
calling **llapi_hsm_current_action**\ (), or by using **lfs
hsm_action**.

Once the HSM request has been performed, the destination file must be
closed, and **llapi_hsm_action_end**\ () must be called to free-up the
allocated ressources and signal Lustre that the file is now available
to consumers. *errval* is set to 0 on success. On error, it must be an
errno, and hp_flags can be set to **HP_FLAG_RETRY** if the request is
retryable, 0 otherwise. *he* is the interval (*offset*, *length*) of
the data copied. It can be the *hai_extent* of the HSM request.

For a restore operation, a volatile file, invisible to ls, is
created. **llapi_hsm_action_get_fd**\ () will return a file descriptor
to it. It is the responsibility of the copytool to close the returned
file descriptor when the data transfer is
done. **llapi_hsm_action_get_dfid**\ () will return the FID of the volatile
file, which can then be used with **llapi_open_by_fid**\ () to open
the file in a different process, or on a different node.

**llapi_hsm_action_get_fd**\ () and **llapi_hsm_action_get_dfid**\ ()
can be called for an archive operation too. The returned file
descriptor and the FID are from the file to be archived.


RETURN VALUE
============

**llapi_hsm_action_get_fd**\ () returns a file descriptor on
success. The other functions return 0 on success. All functions return
a negative errno on failure.


ERRORS
======

The negative errno can be, but is not limited to:

**-EINVAL** An invalid value was passed, the copytool is not
   registered, ...

**-ENOMEM** Not enough memory to allocate a resource.


SEE ALSO
========

**llapi_hsm_copytool_register**\ (3), **llapi_hsm_copytool_recv**\ (3),
**lustreapi**\ (7), **lfs**\ (1)

See *lhsmtool_posix.c* in the Lustre sources for a use case of this
API.
