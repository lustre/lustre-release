// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/lutf/lutf_global.swg
 *
 * Author: Amir Shehata <ashehata@whamcloud.com>
 *
 */

%module clutf_global

%{
#include <netinet/in.h>
typedef unsigned int bool;
#define true 1
#define false 0
#include "lutf_global.h"
%}

#include "lutf_global.h"

