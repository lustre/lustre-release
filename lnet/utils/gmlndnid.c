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
        fprintf(stderr, "usage %s -n hostname | -l | -h\n", prg);
        if (h) {
                printf("\nGet Myrinet Global network ids for specified host\n"
                       "-l gets network id for local host\n");
        }
}

unsigned
u_getgmnid(char *name, int get_local_id)
{
        struct gm_port *gm_port;
        int             gm_port_id = 2;
        gm_status_t     gm_status = GM_SUCCESS;
        unsigned        global_nid = 0, local_nid = 0; /* gm ids never 0 */

        gm_status = gm_init();
        if (gm_status != GM_SUCCESS) {
                fprintf(stderr, "gm_init: %s\n", gm_strerror(gm_status));
                return(0);
        }

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
                        gm_finalize();
                        return(0);
                }
        }

        if (get_local_id) {
                local_nid = 1;
        } else {
                gm_status = gm_host_name_to_node_id_ex(gm_port, 1000000, name,
                                                       &local_nid);
                if (gm_status != GM_SUCCESS) {
                        fprintf(stderr, "gm_host_name_to_node_id_ex: %s\n",
                                gm_strerror(gm_status));
                        gm_close(gm_port);
                        gm_finalize();
                        return(0);
                }
        }

        gm_status = gm_node_id_to_global_id(gm_port, local_nid, &global_nid) ;
        if (gm_status != GM_SUCCESS) {
                fprintf(stderr, "gm_node_id_to_global_id: %s\n",
                        gm_strerror(gm_status));
                gm_close(gm_port);
                gm_finalize();
                return(0);
        }
        gm_close(gm_port);
        gm_finalize();
        return(global_nid);
}

int main(int argc, char **argv)
{
        unsigned int        nid = 0;
        char               *name = NULL;
        int                 c;
        int                 get_local_id = 0;

        while ((c = getopt(argc, argv, "n:lh")) != -1) {
                switch(c) {
                case('n'):
                        if (get_local_id) {
                                usage(argv[0], 0);
                                exit(-1);
                        }
                        name = optarg;
                        break;
                case('h'):
                        usage(argv[0], 1);
                        exit(-1);
                        break;
                case('l'):
                        if (name) {
                                usage(argv[0], 0);
                                exit(-1);
                        }
                        get_local_id = 1;
                        break;
                default:
                        usage(argv[0], 0);
                        exit(-1);
                }
        }

        if (!name && !get_local_id) {
                usage(argv[0], 0);
                exit(-1);
        }

        nid = u_getgmnid(name, get_local_id);
        printf("%u\n", nid);
        exit(0);
}
