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
#include <asm/byteorder.h>
#include <syslog.h>

#include <errno.h>

#include <portals/api-support.h>
#include <portals/list.h>
#include <portals/lib-types.h>

#define LGMNAL_IOC_GET_GNID 1

int
roundup(int len)
{
	return((len+7) & (~0x7));
}

int main(int argc, char **argv)
{
        int rc, pfd;
        struct portal_ioctl_data data;
	unsigned int	nid = 0, len;
	char	*name = NULL;
	int	c;



	while ((c = getopt(argc, argv, "n:l")) != -1) {
		switch(c) {
		case('n'):
			name = optarg;	
		break;
		case('l'):
			printf("Get local id not implemented yet!\n");
			exit(-1);
		default:
			printf("usage %s -n nodename [-p]\n", argv[0]);
		}
	}

	if (!name) {
		printf("usage %s -n nodename [-p]\n", argv[0]);
		exit(-1);
	}



        PORTAL_IOC_INIT (data);

	/*
	 *	set up the inputs
	 */
	len = strlen(name) + 1;
	data.ioc_pbuf1 = malloc(len);
	strcpy(data.ioc_pbuf1, name);
	data.ioc_plen1 = len;

	/*
	 *	set up the outputs
	 */
	data.ioc_pbuf2 = (void*)&nid;
	data.ioc_plen2 = sizeof(unsigned int*);

        pfd = open("/dev/portals", O_RDWR);
        if ( pfd < 0 ) {
                perror("opening portals device");
		free(data.ioc_pbuf1);
                exit(-1);
        }

        data.ioc_nal = LGMNAL;
	data.ioc_nal_cmd = LGMNAL_IOC_GET_GNID;
/*
	data.ioc_len += data.ioc_inllen1;
	data.ioc_len += data.ioc_plen1;
*/
        rc = ioctl (pfd, IOC_PORTAL_NAL_CMD, &data);
        if (rc < 0)
        {
        	perror ("Can't get my NID");
        }
                        
	free(data.ioc_pbuf1);
	close(pfd);
	printf("%u\n", nid);
        exit(nid);
}
