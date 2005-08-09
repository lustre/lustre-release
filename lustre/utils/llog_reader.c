/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <time.h>
#include <liblustre.h>
#include <linux/lustre_idl.h>

int llog_pack_buffer(int fd, struct llog_log_hdr** llog_buf, struct llog_rec_hdr*** recs, int* recs_number);

void print_llog_header(struct llog_log_hdr* llog_buf);
void print_records(struct llog_rec_hdr** recs_buf,int rec_number);
void llog_unpack_buffer(int fd,struct llog_log_hdr* llog_buf,struct llog_rec_hdr** recs_buf);

#define PTL_CMD_BASE 100
char* portals_command[17]=
{
        "REGISTER_PEER_FD",
        "CLOSE_CONNECTION",
        "REGISTER_MYNID",
        "PUSH_CONNECTION",
        "GET_CONN",
        "DEL_PEER",
        "ADD_PEER",
        "GET_PEER",
        "GET_TXDESC",
        "ADD_ROUTE",
        "DEL_ROUTE",
        "GET_ROUTE",
        "NOTIFY_ROUTER",
        "ADD_INTERFACE",
        "DEL_INTERFACE",
        "GET_INTERFACE",
        ""
};
                
int main(int argc, char **argv)
{
        int rc=0;
	int fd,rec_number;
	
	struct llog_log_hdr* llog_buf=NULL;
	struct llog_rec_hdr** recs_buf=NULL;
		

        setlinebuf(stdout);
	
	if(argc != 2 ){
		printf("Usage: llog_reader filename \n");
                return -1;
        }
	
	fd = open(argv[1],O_RDONLY);
	if (fd < 0){
		printf("Could not open the file %s \n",argv[1]);
		goto out;
	}
	rc = llog_pack_buffer(fd,&llog_buf,&recs_buf,&rec_number);
		
        if(llog_buf == NULL )
                printf("error");
	print_llog_header(llog_buf);
	
	print_records(recs_buf,rec_number);

	llog_unpack_buffer(fd,llog_buf,recs_buf);
	close(fd);
out:
        return rc;
}



int llog_pack_buffer(int fd, struct llog_log_hdr** llog, 
			struct llog_rec_hdr*** recs, 
			int* recs_number)
{
	int rc=0,recs_num,rd;
	off_t file_size;
	struct stat st;
	char  *file_buf=NULL, *recs_buf=NULL;
        struct llog_rec_hdr** recs_pr=NULL;
	char* ptr=NULL;

	int cur_idx,i;
	
	rc = fstat(fd,&st);
	if (rc < 0){
		printf("Get file stat error.\n");
		goto out;
	}	
	file_size = st.st_size;
	
	file_buf = malloc(file_size);
	if (file_buf == NULL){
		printf("Memory Alloc for file_buf error.\n");
		rc = -ENOMEM;
		goto out;
	}	
	*llog = (struct llog_log_hdr*)file_buf;

	rd = read(fd,file_buf,file_size);
	if (rd < file_size){
		printf("Read file error.\n");
		rc = -EIO; /*FIXME*/
		goto clear_file_buf;
	}	

        /* the llog header not countable here.*/
	recs_num = le32_to_cpu((*llog)->llh_count)-1;
	
	recs_buf = malloc(recs_num*sizeof(struct llog_rec_hdr*));
	if (recs_buf == NULL){
		printf("Memory Alloc for recs_buf error.\n");
		rc = -ENOMEM;
		goto clear_file_buf;
	}	
	recs_pr = (struct llog_rec_hdr **)recs_buf;
	
	ptr = file_buf + le32_to_cpu((*llog)->llh_hdr.lrh_len);
	cur_idx = 1;
	i = 0;
	while (i < recs_num){	
		struct llog_rec_hdr* cur_rec=(struct llog_rec_hdr*)ptr;

		while (! ext2_test_bit(cur_idx,(*llog)->llh_bitmap) ){
			cur_idx++;
			ptr+=cur_rec->lrh_len;
			if ((ptr-file_buf) > file_size){
				printf("The log is corrupted. \n");
				rc = -EINVAL;
				goto clear_recs_buf;
			}	
		}
		recs_pr[i] = cur_rec;
		ptr+=cur_rec->lrh_len;
		i++;
                cur_idx++;
	}
        
        *recs = recs_pr;
	*recs_number=recs_num;

out:
	return rc;

clear_recs_buf:
	free(recs_buf);

clear_file_buf:
	free(file_buf);

        *llog=NULL;
	goto out;

}


void llog_unpack_buffer(int fd,struct llog_log_hdr* llog_buf,struct llog_rec_hdr **recs_buf)
{
        free(llog_buf);
        free(recs_buf);
        return;
}


void print_llog_header(struct llog_log_hdr* llog_buf)
{
	time_t t;

	printf("\n      **The LOGS Header Informations**\n");

	printf("        Hearder size : %d \n",
	//		le32_to_cpu(llog_buf->llh_hdr.lrh_len));
			llog_buf->llh_hdr.lrh_len);

	t = le64_to_cpu(llog_buf->llh_timestamp);
	printf("        Time : %s ", ctime(&t));

	printf("        Number of records: %d \n",
			le32_to_cpu(llog_buf->llh_count)-1);

	printf("        Target uuid : %s \n",
                        (char *)(&llog_buf->llh_tgtuuid));

	/* Add the other infor you want to view here*/
	
	return;
}
void print_lustre_cfg(struct lustre_cfg *lcfg)
{
	enum lcfg_command_type cmd = le32_to_cpu(lcfg->lcfg_command);
        char * ptr = (char *)lcfg + LCFG_HDR_SIZE(lcfg->lcfg_bufcount);
        
	switch(cmd){
	case(LCFG_ATTACH):{
                if (lustre_cfg_string(lcfg, 0))
        		printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
		printf("        attach ");
                if (lustre_cfg_string(lcfg, 1))
		        printf("%s \n", lustre_cfg_string(lcfg, 1));
                if (lustre_cfg_string(lcfg, 0))
		        printf("%s \n", lustre_cfg_string(lcfg, 0));
                if (lustre_cfg_string(lcfg, 2))
		        printf("%s \n", lustre_cfg_string(lcfg, 2));
		printf("\n");
		break;
	}
	case(LCFG_SETUP):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("        setup ");
                if (lustre_cfg_string(lcfg, 1))
                        printf("%s \n", lustre_cfg_string(lcfg, 1));
                if (lustre_cfg_string(lcfg, 2))
                        printf("%s \n", lustre_cfg_string(lcfg, 2));
                if (lustre_cfg_string(lcfg, 3))
                        printf("%s \n", lustre_cfg_string(lcfg, 3));
                if (lustre_cfg_string(lcfg, 4))
                        printf("%s \n", lustre_cfg_string(lcfg, 4));
		printf("\n");
		break;
	}
        case(LCFG_DETACH):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        detach ");
                printf("\n");
                break;
        }
        case(LCFG_CLEANUP):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        cleanup ");
		if (lustre_cfg_string(lcfg, 1)){
			if(!strncmp(lustre_cfg_string(lcfg, 1), "F", 1))
                                printf("force ");
			if(!strncmp(lustre_cfg_string(lcfg, 1), "A", 1))
                                printf("failover ");
                }
                printf("\n");
                break;
        }
        case(LCFG_ADD_UUID):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        add_uuid ");
		if (lustre_cfg_string(lcfg, 1))
			printf(" ( uuid: %s, ", lustre_cfg_string(lcfg, 1));
                printf("nid: %x, ", lcfg->lcfg_nid);
                printf("nal type: %d )", lcfg->lcfg_nal);
                printf("\n");
                break;
        }
        case(LCFG_DEL_UUID):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        del_uuid ");
                if (lustre_cfg_string(lcfg, 1))
                        printf("%s \n", lustre_cfg_string(lcfg, 1));
                printf("\n");
                break;
        }
        case(LCFG_LOV_ADD_OBD):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("        lov_add_obd ");
                if (lustre_cfg_string(lcfg, 1))
                        printf("%s \n", lustre_cfg_string(lcfg, 1));
                if (lustre_cfg_string(lcfg, 2))
                        printf("%s \n", lustre_cfg_string(lcfg, 2));
                if (lustre_cfg_string(lcfg, 3))
                        printf("%s \n", lustre_cfg_string(lcfg, 3));
                printf("\n");
                break;
        }
        case(LCFG_LOV_DEL_OBD):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        lov_del_obd ");
                if (lustre_cfg_string(lcfg, 1))
                        printf("%s \n", lustre_cfg_string(lcfg, 1));
                if (lustre_cfg_string(lcfg, 2))
                        printf("%s \n", lustre_cfg_string(lcfg, 2));
                if (lustre_cfg_string(lcfg, 3))
                        printf("%s \n", lustre_cfg_string(lcfg, 3));
                printf("\n");
                break;
        }
        case(LCFG_MOUNTOPT):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        mount_option ");
                if (lustre_cfg_string(lcfg, 1))
                        printf("%s \n", lustre_cfg_string(lcfg, 1));
                if (lustre_cfg_string(lcfg, 2))
                        printf("%s \n", lustre_cfg_string(lcfg, 2));
                if (lustre_cfg_string(lcfg, 3))
                        printf("%s \n", lustre_cfg_string(lcfg, 3));
                printf("\n");
                break;
        }
        case(LCFG_DEL_MOUNTOPT):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        del_mount_option ");
                if (lustre_cfg_string(lcfg, 1))
                        printf("%s \n", lustre_cfg_string(lcfg, 1));
                printf("\n");
                break;
        }
        case(LCFG_SET_TIMEOUT):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        set_timeout %d", lcfg->lcfg_num);
                printf("\n");
                break;
        }
        case(LCFG_SET_UPCALL):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        set_lustre_upcall ");
                if (lustre_cfg_string(lcfg, 1))
                        printf("%s \n", lustre_cfg_string(lcfg, 1));
                printf("\n");
                break;
        }
        case(LCFG_ADD_CONN):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        add_conn ");
                if (lustre_cfg_string(lcfg, 1))
                        printf("%s \n", lustre_cfg_string(lcfg, 1));
                if (lustre_cfg_string(lcfg, 2))
                        printf("%s \n", lustre_cfg_string(lcfg, 2));
                printf("\n");
                break;
        }
        case(LCFG_DEL_CONN):{
                if (lustre_cfg_string(lcfg, 0))
                        printf(" dev:%s \n", lustre_cfg_string(lcfg, 0));
                printf("\n ");
                printf("        del_conn ");
                if (lustre_cfg_string(lcfg, 1))
                        printf("%s \n", lustre_cfg_string(lcfg, 1));
                printf("\n");
                break;
        }
	default:
		printf("not support this command, cmd_code = %x\n",cmd);
	}
	return;
}

void print_records(struct llog_rec_hdr** recs,int rec_number)
{
        __u32 lopt;
	int i;
        
	for(i=0;i<rec_number;i++){
        
	        printf("      %d:", le32_to_cpu(recs[i]->lrh_index));

                lopt = le32_to_cpu(recs[i]->lrh_type);

                if (lopt == OBD_CFG_REC){
	                struct lustre_cfg *lcfg;
                        printf("LUSTRE"); 
	        	lcfg = (struct lustre_cfg *)
                                ((char*)(recs[i]) + sizeof(struct llog_rec_hdr));
               		print_lustre_cfg(lcfg);
                }

                if (lopt == PTL_CFG_REC){
	                struct portals_cfg *pcfg;
                        printf("PORTALS"); 
                        pcfg = (struct portals_cfg *)
                                ((char*)(recs[i]) + sizeof(struct llog_rec_hdr));
                        printf(" Command: %s \n",
                               portals_command[pcfg->pcfg_command- PTL_CMD_BASE]);
                }
	}
}
