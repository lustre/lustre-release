// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024, Amazon and/or its affiliates. All rights reserved.
// Use is subject to license terms.
//
// Don't check for NULL with common free'ing macros.
//
// Author: Timothy Day <timday@amazon.com>
//

@@
expression E;
@@
- if (E != NULL)
(
  OBD_FREE_PTR(E);
|
  OBD_FREE(E, ...);
|
  LIBCFS_FREE(E, ...);
|
  CFS_FREE_PTR(E);
|
  CFS_FREE_PTR_ARRAY(E, ...);
)
