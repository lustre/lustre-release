/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
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
 /* Interpret configuration llogs */


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <time.h>
#include <liblustre.h>
#include <lustre/lustre_idl.h>

int llog_pack_buffer(int fd, struct llog_log_hdr **llog_buf,
                     struct llog_rec_hdr ***recs, int *recs_number);

void print_llog_header(struct llog_log_hdr *llog_buf);
void print_records(struct llog_rec_hdr **recs_buf,int rec_number);
void llog_unpack_buffer(int fd, struct llog_log_hdr *llog_buf,
                        struct llog_rec_hdr **recs_buf);

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
        int rc = 0;
        int fd, rec_number;
        struct llog_log_hdr *llog_buf = NULL;
        struct llog_rec_hdr **recs_buf = NULL;

        setlinebuf(stdout);

        if(argc != 2 ){
                printf("Usage: llog_reader filename\n");
                return -1;
        }

        fd = open(argv[1],O_RDONLY);
        if (fd < 0){
                printf("Could not open the file %s\n", argv[1]);
                goto out;
        }
        rc = llog_pack_buffer(fd, &llog_buf, &recs_buf, &rec_number);
        if (rc < 0) {
                printf("Could not pack buffer; rc=%d\n", rc);
                goto out_fd;
        }

        print_llog_header(llog_buf);
        print_records(recs_buf,rec_number);
        llog_unpack_buffer(fd,llog_buf,recs_buf);
out_fd:
        close(fd);
out:
        return rc;
}



int llog_pack_buffer(int fd, struct llog_log_hdr **llog,
                     struct llog_rec_hdr ***recs,
                     int *recs_number)
{
        int rc = 0, recs_num,rd;
        off_t file_size;
        struct stat st;
        char *file_buf=NULL, *recs_buf=NULL;
        struct llog_rec_hdr **recs_pr=NULL;
        char *ptr=NULL;
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

        recs_buf = malloc(recs_num * sizeof(struct llog_rec_hdr *));
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
                struct llog_rec_hdr *cur_rec = (struct llog_rec_hdr*)ptr;

                if (ext2_test_bit(cur_idx++, (*llog)->llh_bitmap)) {
                        recs_pr[i++] = cur_rec;
                        ptr += cur_rec->lrh_len;
                        if ((ptr - file_buf) > file_size) {
                                printf("The log is corrupted.\n");
                                rc = -EINVAL;
                                goto clear_recs_buf;
                        }
                }
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

void llog_unpack_buffer(int fd, struct llog_log_hdr *llog_buf,
                        struct llog_rec_hdr **recs_buf)
{
        free(llog_buf);
        free(recs_buf);
        return;
}

void print_llog_header(struct llog_log_hdr *llog_buf)
{
        time_t t;

        printf("Header size : %u\n",
                llog_buf->llh_hdr.lrh_len);

        t = le64_to_cpu(llog_buf->llh_timestamp);
        printf("Time : %s", ctime(&t));

        printf("Number of records: %u\n",
               le32_to_cpu(llog_buf->llh_count)-1);

        printf("Target uuid : %s \n",
               (char *)(&llog_buf->llh_tgtuuid));

        /* Add the other info you want to view here */

        printf("-----------------------\n");
        return;
}

static void print_1_cfg(struct lustre_cfg *lcfg)
{
        int i;

        if (lcfg->lcfg_nid)
                printf("nid=%s("LPX64")  ", libcfs_nid2str(lcfg->lcfg_nid),
                       lcfg->lcfg_nid);
        if (lcfg->lcfg_nal)
                printf("nal=%d ", lcfg->lcfg_nal);
        for (i = 0; i <  lcfg->lcfg_bufcount; i++)
                printf("%d:%.*s  ", i, lcfg->lcfg_buflens[i],
                       (char*)lustre_cfg_buf(lcfg, i));
        return;
}


static void print_setup_cfg(struct lustre_cfg *lcfg)
{
        struct lov_desc *desc;

        if ((lcfg->lcfg_bufcount == 2) &&
            (lcfg->lcfg_buflens[1] == sizeof(*desc))) {
                printf("lov_setup ");
                printf("0:%s  ", lustre_cfg_string(lcfg, 0));
                printf("1:(struct lov_desc)\n");
                desc = (struct lov_desc*)(lustre_cfg_string(lcfg, 1));
                printf("\t\tuuid=%s  ", (char*)desc->ld_uuid.uuid);
                printf("stripe:cnt=%u ", desc->ld_default_stripe_count);
                printf("size="LPU64" ", desc->ld_default_stripe_size);
                printf("offset="LPU64" ", desc->ld_default_stripe_offset);
                printf("pattern=%#x", desc->ld_pattern);
        } else {
                printf("setup ");
                print_1_cfg(lcfg);
        }
        
        return;
}

void print_lustre_cfg(struct lustre_cfg *lcfg, int *skip)
{
        enum lcfg_command_type cmd = le32_to_cpu(lcfg->lcfg_command);

        if (*skip > 0)
                printf("SKIP ");

        switch(cmd){
        case(LCFG_ATTACH):{
                printf("attach    ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_SETUP):{
                print_setup_cfg(lcfg);
                break;
        }
        case(LCFG_DETACH):{
                printf("detach    ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_CLEANUP):{
                printf("cleanup   ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_ADD_UUID):{
                printf("add_uuid  ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_DEL_UUID):{
                printf("del_uuid  ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_ADD_CONN):{
                printf("add_conn  ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_DEL_CONN):{
                printf("del_conn  ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_LOV_ADD_OBD):{
                printf("lov_modify_tgts add ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_LOV_DEL_OBD):{
                printf("lov_modify_tgts del ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_ADD_MDC):{
                printf("modify_mdc_tgts add ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_DEL_MDC):{
                printf("modify_mdc_tgts del ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_MOUNTOPT):{
                printf("mount_option ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_DEL_MOUNTOPT):{
                printf("del_mount_option ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_SET_TIMEOUT):{
                printf("set_timeout=%d ", lcfg->lcfg_num);
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_SET_UPCALL):{
                printf("set_lustre_upcall ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_PARAM):{
                printf("param ");
                print_1_cfg(lcfg);
                break;
        }
        case(LCFG_MARKER):{
                struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);

                if (marker->cm_flags & CM_SKIP) {
                        if (marker->cm_flags & CM_START) 
                                (*skip)++;
                        if (marker->cm_flags & CM_END)
                                (*skip)--;
                }
                printf("marker %d (flags=%#x, v%d.%d.%d.%d) %.16s '%s' %s:%s",
                       marker->cm_step, marker->cm_flags,
                       OBD_OCD_VERSION_MAJOR(marker->cm_vers),
                       OBD_OCD_VERSION_MINOR(marker->cm_vers),
                       OBD_OCD_VERSION_PATCH(marker->cm_vers),
                       OBD_OCD_VERSION_FIX(marker->cm_vers),
                       marker->cm_svname, 
                       marker->cm_comment, ctime(&marker->cm_createtime),
                       marker->cm_canceltime ? 
                       ctime(&marker->cm_canceltime) : "");
                break;
        }
        default:
                printf("unsupported cmd_code = %x\n",cmd);
        }
        printf("\n");
        return;
}

void print_records(struct llog_rec_hdr **recs, int rec_number)
{
        __u32 lopt;
        int i, skip = 0;
        
        for(i = 0; i < rec_number; i++) {
                printf("#%.2d ", le32_to_cpu(recs[i]->lrh_index));

                lopt = le32_to_cpu(recs[i]->lrh_type);

                if (lopt == OBD_CFG_REC){
                        struct lustre_cfg *lcfg;
                        printf("L ");
                        lcfg = (struct lustre_cfg *)((char*)(recs[i]) +
                                                     sizeof(struct llog_rec_hdr));
                        print_lustre_cfg(lcfg, &skip);
                }

                if (lopt == PTL_CFG_REC)
                        printf("Portals - unknown type\n");
        }
}
