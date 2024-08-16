// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024, Amazon and/or its affiliates. All rights reserved.
// Use is subject to license terms.
//
// Remove pointless macros. Demonstrates a simple find-and-replace with
// Coccinelle.
//
// Author: Timothy Day <timday@amazon.com>
//

@@
expression x;
@@
- LDLM_LOCK_PUT(x)
+ ldlm_lock_put(x)
@@
expression x;
@@
- LDLM_LOCK_RELEASE(x)
+ ldlm_lock_put(x)
@@
expression x;
@@
- LDLM_LOCK_GET(x)
+ ldlm_lock_get(x)
