// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (c) 2013, Intel Corporation.
 * Use is subject to license terms.
 */

/* A simple program to test the headers and libraray are
 *  available.
 */

#include <lustre/lustreapi.h>

int main(int argc, char *argv[])
{
	struct lov_user_md lum;

	return llapi_file_get_stripe(argv[1], &lum);
}
