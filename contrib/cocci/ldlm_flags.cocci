// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024, Amazon and/or its affiliates. All rights reserved.
// Use is subject to license terms.
//
// Replace macros with explicit flag manipulation. Demonstrates Python
// scripting available with Coccinelle.
//
// Author: Timothy Day <timday@amazon.com>
//

@ldlm_is@
identifier MACRO =~ "ldlm_is";
@@
MACRO(...)

@script:python get_flag_is@
IDENT << ldlm_is.MACRO;
MACRO;
FLAG;
@@
coccinelle.MACRO = IDENT

if "granted" in IDENT:
   cocci.include_match(False)

IDENT = IDENT.split("_")
IDENT = IDENT[2:]
IDENT = ["LDLM", "FL"] + IDENT
IDENT = "_".join(IDENT).upper()
coccinelle.FLAG = IDENT

print(coccinelle.MACRO, coccinelle.FLAG)

@convert_is@
identifier get_flag_is.FLAG;
identifier get_flag_is.MACRO;
identifier L;
@@
- MACRO(L)
+ (L->l_flags & FLAG)

@ldlm_set@
identifier MACRO =~ "ldlm_set";
@@
MACRO(...)

@script:python get_flag_set@
IDENT << ldlm_set.MACRO;
MACRO;
FLAG;
@@
coccinelle.MACRO = IDENT

IDENT = IDENT.split("_")
IDENT = IDENT[2:]
IDENT = ["LDLM", "FL"] + IDENT
IDENT = "_".join(IDENT).upper()
coccinelle.FLAG = IDENT

print(coccinelle.MACRO, coccinelle.FLAG)

@convert_set@
identifier get_flag_set.FLAG;
identifier get_flag_set.MACRO;
identifier L;
@@
- MACRO(L)
+ (L->l_flags |= FLAG)

@ldlm_clear@
identifier MACRO =~ "ldlm_clear";
@@
MACRO(...)

@script:python get_flag_clear@
IDENT << ldlm_clear.MACRO;
MACRO;
FLAG;
@@
coccinelle.MACRO = IDENT

if "blocking_lock" in IDENT:
   cocci.include_match(False)
if "blocking_data" in IDENT:
   cocci.include_match(False)

IDENT = IDENT.split("_")
IDENT = IDENT[2:]
IDENT = ["LDLM", "FL"] + IDENT
IDENT = "_".join(IDENT).upper()
coccinelle.FLAG = IDENT

print(coccinelle.MACRO, coccinelle.FLAG)

@convert_clear@
identifier get_flag_clear.FLAG;
identifier get_flag_clear.MACRO;
identifier L;
@@
- MACRO(L)
+ (L->l_flags &= ~FLAG)
