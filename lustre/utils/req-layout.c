/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  req_layout.c
 *  User-level tool for printing request layouts
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <lustre/lustre_idl.h>

#define __REQ_LAYOUT_USER__ (1)

#define ARRAY_SIZE(a) ((sizeof (a))/(sizeof (a)[0]))
#define lustre_swab_generic_32s NULL
#define lustre_swab_lu_range NULL
#define lustre_swab_md_fld NULL
#define lustre_swab_mdt_body NULL
#define lustre_swab_obd_statfs NULL
#define lustre_swab_connect NULL
#define lustre_swab_ldlm_request NULL
#define lustre_swab_ldlm_reply NULL
#define lustre_swab_ldlm_intent NULL
#define lustre_swab_lov_mds_md NULL
#define lustre_swab_mds_rec_unlink NULL
#define lustre_swab_mdt_rec_link NULL
#define lustre_swab_mdt_rec_rename NULL
#define lustre_swab_mdt_rec_create NULL
#define lustre_swab_mdt_rec_setattr NULL

#define EXPORT_SYMBOL(name)

/*
 * Yes, include .c file.
 */
#include "../ptlrpc/layout.c"

void usage(void)
{
        fprintf(stderr, "req-layout -- prints lustre request layouts\n");
}

void printt_field(const char *prefix, const struct req_msg_field *fld)
{
}

void print_layout(const struct req_format *rf)
{
        int j;
        int k;

        int offset;
        int variable;

        static const char *prefix[RCL_NR] = {
                [RCL_CLIENT] = "C",
                [RCL_SERVER] = "S"
        };

        printf("L %s (%i/%i)\n", rf->rf_name,
               rf->rf_fields[RCL_CLIENT].nr, rf->rf_fields[RCL_SERVER].nr);

        for (j = 0; j < RCL_NR; ++j) {
                offset = 0;
                variable = 0;
                for (k = 0; k < rf->rf_fields[j].nr; ++k) {
                        const struct req_msg_field *fld;

                        fld = rf->rf_fields[j].d[k];

                        printf("        F%s %0i [%03.3i%s %-20.20s (",
                               prefix[j], k, offset,
                               variable ? " + ...]" : "]      ",
                               fld->rmf_name);
                        if (fld->rmf_size > 0) {
                                printf("%3.3i) ", fld->rmf_size);
                                offset += fld->rmf_size;
                        } else {
                                printf("var) ");
                                variable = 1;
                        }
                        if (fld->rmf_flags & RMF_F_STRING)
                                printf("string");
                        printf("\n");
                }
                if (k > 0 && j != RCL_NR - 1)
                        printf("        -----------------------------------\n");
        }
}

void print_layouts(void)
{
        int i;

        for (i = 0; i < ARRAY_SIZE(req_formats); ++i) {
                print_layout(req_formats[i]);
                printf("\n");
        }
}

int main(int argc, char **argv)
{
        int opt;
        int verbose;

        verbose = 0;
        do {
                opt = getopt(argc, argv, "hb:k:r:p:v");
                switch (opt) {
                case 'v':
                        verbose++;
                case -1:
                        break;
                case '?':
                default:
                        fprintf(stderr, "Unable to parse options.");
                case 'h':
                        usage();
                        return 0;
                }
        } while (opt != -1);
        print_layouts();
        return 0;
}
