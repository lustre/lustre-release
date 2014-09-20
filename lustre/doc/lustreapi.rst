=========
lustreapi
=========

----------------------
The Lustre API library
----------------------

:Author: Lustre contributors
:Date:   2014-09-21
:Manual section: 7
:Manual group: The Lustre API library

SYNOPSIS
========

**#include <lustre/lustreapi.h>**

DESCRIPTION
===========

The lustreapi library provides functions to access and/or modify
settings specific to the Lustre filesystem (allocation policies,
quotas, etc).

The library provides the following functions:

**HSM**

  int llapi_hsm_copytool_register(struct hsm_copytool_private \*\*priv,
  const char \*mnt, int archive_count, int \*archives,
  int rfd_flags)

  int llapi_hsm_copytool_unregister(struct hsm_copytool_private \*\*priv)

  int llapi_hsm_copytool_get_fd(struct hsm_copytool_private \*ct)

  int llapi_hsm_copytool_recv(struct hsm_copytool_private \*priv,
  struct hsm_action_list \*\*hal, int \*msgsize)

  struct hsm_action_item \*hai_first(struct hsm_action_list \*hal)

  struct hsm_action_item \*hai_next(struct hsm_action_item \*hai)

  int llapi_hsm_action_begin(struct hsm_copyaction_private \*\*phcp,
  const struct hsm_copytool_private \*ct, const struct
  hsm_action_item \*hai, int restore_mdt_index, int
  restore_open_flags, bool is_error)

  int llapi_hsm_action_end(struct hsm_copyaction_private \*\*phcp,
  const struct hsm_extent \*he, int hp_flags, int errval)

  int llapi_hsm_action_progress(struct hsm_copyaction_private \*hcp,
  const struct hsm_extent \*he, __u64 total, int hp_flags)

  int llapi_hsm_action_get_dfid(const struct hsm_copyaction_private \*hcp,
  lustre_fid \*fid)

  int llapi_hsm_action_get_fd(const struct hsm_copyaction_private \*hcp)


SEE ALSO
========

**lustre**\ (7),
**llapi_file_create**\ (3),
**llapi_file_open**\ (3),
**llapi_file_get_stripe**\ (3),
**llapi_layout**\ (3),
**llapi_quotactl**\ (3),
**llapi_hsm_state_get**\ (3),
**llapi_hsm_state_set**\ (3)
