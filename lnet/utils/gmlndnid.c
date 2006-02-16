/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
  * vim:expandtab:shiftwidth=8:tabstop=8:
  *
  *  Copyright (c) 2003 Los Alamos National Laboratory (LANL)
  *
  *   This file is part of Lustre, http://www.lustre.org/
  *
  *   This file is free software; you can redistribute it and/or
  *   modify it under the terms of version 2.1 of the GNU Lesser General
  *   Public License as published by the Free Software Foundation.
  *
  *   Lustre is distributed in the hope that it will be useful,
  *   but WITHOUT ANY WARRANTY; without even the implied warranty of
  *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *   GNU Lesser General Public License for more details.
  *
  *   You should have received a copy of the GNU Lesser General Public
  *   License along with Portals; if not, write to the Free Software
  *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
  */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <lnet/api-support.h>
#include <lnet/lib-types.h>

#include <gm.h>

/*
 *      portals always uses unit 0
 *      Can this be configurable?
 */
#define GM_UNIT 0

void
usage(char *prg, int h)
{
        fprintf(stderr,
                "usage %s -h\n"
                "      %s [-l] [-n hostname] [-L] [hostnames]\n", prg);

        if (h)
                printf("Print Myrinet Global network ids for specified hosts\n"
                       "-l                    print local host's ID\n"
                       "-n hostname           print given host's ID\n"
                       "-L                    print Myringet local net ID too\n"
                       "[hostnames]           print ids of given hosts (local if none)\n");
}

gm_status_t
print_gmid(char *name, int name_fieldlen, int show_local_id)
{
        struct gm_port *gm_port;
        int             gm_port_id;
        gm_status_t     gm_status;
        unsigned int    local_id;
        unsigned int    global_id;

        gm_status = gm_init();
        if (gm_status != GM_SUCCESS) {
                fprintf(stderr, "gm_init: %s\n", gm_strerror(gm_status));
                return gm_status;
        }

        gm_port_id = 2;
        gm_status = gm_open(&gm_port, GM_UNIT, gm_port_id, "gmnalnid",
                            GM_API_VERSION);
        if (gm_status != GM_SUCCESS) {
                int num_ports = gm_num_ports(gm_port);

                /* Couldn't open port 2, try 4 ... num_ports */
                for (gm_port_id = 4; gm_port_id < num_ports; gm_port_id++) {
                        gm_status = gm_open(&gm_port, GM_UNIT, gm_port_id,
                                            "gmnalnid", GM_API_VERSION);
                        if (gm_status == GM_SUCCESS)
                                break;
                }

                if (gm_status != GM_SUCCESS) {
                        fprintf(stderr, "gm_open: %s\n",gm_strerror(gm_status));
                        goto out_0;
                }
        }

        if (name == NULL) {
                local_id = 1;
                name = "<local>";
        } else {
                gm_status = gm_host_name_to_node_id_ex(gm_port, 1000000, name,
                                                       &local_id);
                if (gm_status != GM_SUCCESS) {
                        fprintf(stderr, "gm_host_name_to_node_id_ex(%s): %s\n",
                                name, gm_strerror(gm_status));
                        goto out_1;
                }
        }

        gm_status = gm_node_id_to_global_id(gm_port, local_id, &global_id) ;
        if (gm_status != GM_SUCCESS) {
                fprintf(stderr, "gm_node_id_to_global_id(%s:%d): %s\n",
                        name, local_id, gm_strerror(gm_status));
                goto out_1;
        }

        if (name_fieldlen > 0)
                printf ("%*s ", name_fieldlen, name);

        if (!show_local_id)
                printf("0x%x\n", global_id);
        else
                printf("local 0x%x global 0x%x\n", local_id, global_id);

 out_1:
        gm_close(gm_port);
 out_0:
        gm_finalize();

        return gm_status;
}

int
main (int argc, char **argv)
{
        int                 c;
        gm_status_t         gmrc;
        int                 rc;
        int                 max_namelen = 0;
        int                 show_local_id = 0;

        while ((c = getopt(argc, argv, "n:lLh")) != -1)
                switch(c) {
                case 'h':
                        usage(argv[0], 1);
                        return 0;

                case 'L':
                        show_local_id = 1;
                        break;

                case 'n':
                        gmrc = print_gmid(optarg, 0, show_local_id);
                        return (gmrc == GM_SUCCESS) ? 0 : 1;

                case 'l':
                        gmrc = print_gmid(NULL, 0, show_local_id);
                        return (gmrc == GM_SUCCESS) ? 0 : 1;

                default:
                        usage(argv[0], 0);
                        return 2;
                }

        if (optind == argc) {
                gmrc = print_gmid(NULL, 0, show_local_id);
                return (gmrc == GM_SUCCESS) ? 0 : 1;
        }

        if (optind != argc - 1)
                for (c = optind; c < argc; c++)
                        if (strlen(argv[c]) > max_namelen)
                                max_namelen = strlen(argv[c]);

        rc = 0;

        for (c = optind; c < argc; c++) {
                gmrc = print_gmid(argv[c], max_namelen, show_local_id);

                if (gmrc != GM_SUCCESS)
                        rc = 1;
        }

        return rc;
}
