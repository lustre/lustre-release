/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

 #define UT_MSG_MODULE_NAME "utcli "
 #include "ut.h"

int pkt_size = 300;
module_param(pkt_size,int,S_IRUGO);
int get=0;
module_param(get,int,S_IRUGO);
int put=0;
module_param(put,int,S_IRUGO);
int auto_unlink=1;
module_param(auto_unlink,int,S_IRUGO);
char* nid=0;
module_param(nid,charp,S_IRUGO);

static int __init utcli_init(void)
{
        lnet_handle_md_t        mdh;
        lnet_process_id_t       target;
        lnet_process_id_t       mypid;
        lnet_handle_eq_t        eqh;
        lnet_md_t               md;
        int                     rc,i;
        char* buffer            = 0;
        /*
         * Put and get really control the same thing
         */
        if(put)get=0;
        /* Default to get */
        if(!put && !get)get=1;

        PJK_UT_MSG("utcli_init %s\n",get==0?"PUT":"GET");
        PJK_UT_MSG("pkt_size=%d\n",pkt_size);
        PJK_UT_MSG("auto_unlink=%d\n",auto_unlink);
        PJK_UT_MSG("nid=%s\n",nid);
        if(nid == 0)
        {
                CERROR("NID Must be specified\n");
                return -EINVAL;
        }

        PJK_UT_MSG("LIBCFS_ALLOC\n");
        LIBCFS_ALLOC (buffer, pkt_size);
        if (buffer == NULL)
        {
                CERROR ("Unable to allocate out_buf (%d bytes)\n", pkt_size);
                return -ENOMEM;
        }

        PJK_UT_MSG("LNetNiInit()\n");
        rc = LNetNIInit(0);
        if (rc < 0)
        {
                CERROR ("LNetNIInit: error %d\n", rc);
                goto exit0;
        }


        LNetGetId(0,&mypid);
        PJK_UT_MSG("my.nid="LPX64"\n",mypid.nid);
        PJK_UT_MSG("my.pid=0x%x\n",mypid.pid);


        PJK_UT_MSG("LNetEQAlloc\n");
        rc = LNetEQAlloc(
                64,      /* max number of envents why 64? */
                handler, /* handler callback */
                &eqh);   /* output handle */
        if(rc != 0) {
                CERROR("LNetEQAlloc failed %d\n",rc);
                goto exit1;
        }

        md.start = buffer;
        md.length = pkt_size;
        md.threshold = auto_unlink ? (get ? 2 : 1) : 15;
        md.max_size = 0;
        md.options = 0;
        if(get){
                md.options |= LNET_MD_OP_GET;
        }else{
                md.options |= LNET_MD_OP_PUT;
                md.options |= LNET_MD_ACK_DISABLE;
        }
        md.user_ptr = 0;
        md.eq_handle = eqh;

        PJK_UT_MSG("LNetMDBind()\n");
        if ((rc=LNetMDBind (
                     md,
                     LNET_UNLINK,
                     &mdh)))               /* out handle */
        {
                CERROR ("LNetMDBind error %d\n", rc);
                goto exit4;
        }

        target.pid = 0;
        target.nid = libcfs_str2nid(nid);

        PJK_UT_MSG("target.nid="LPX64"\n",target.nid);

        for(i=0;i<1;i++)
        {
                if(get){
                        PJK_UT_MSG("LNetGet()\n");
                        if((rc = LNetGet (
                                    LNET_ID_ANY,
                                    mdh,
                                    target,       /* peer "address" */
                                    UT_PORTAL,    /* portal */
                                    i,            /* match bits */
                                    0)))          /* header data */
                        {
                                CERROR("LNetGet %d error %d\n",i, rc);
                                goto exit5;
                        }
                }else{

                        PJK_UT_MSG("LNetPut()\n");
                        if((rc = LNetPut (
                                    LNET_ID_ANY,
                                    mdh,
                                    LNET_ACK_REQ, /* we want ack */
                                    target,       /* peer "address" */
                                    UT_PORTAL,    /* portal */
                                    i,            /* match bits */
                                    0,            /* offset */
                                    0)))          /* header data */
                        {
                                CERROR("LNetPut %d error %d\n",i, rc);
                                goto exit5;
                        }
                }
        }


        PJK_UT_MSG("------------Waiting for SEND_END()------------\n");
        i=0;
        while(i++ < 10 && seen == 0)
                cfs_pause(cfs_time_seconds(1));
        if(seen == 0)
                PJK_UT_MSG("------------------TIMEDOUT--------------------\n");
        else{
                int good;
                if(get){
                        PJK_UT_MSG("------------Waiting for REPLY()------------\n");
                        i=0;
                        while(i++ < 10 && seen == 1)
                                cfs_pause(cfs_time_seconds(1));
                        good = (seen != 1);
                }else{
                        good = 1;
                }

                if(good)
                        PJK_UT_MSG("------------------COMPLETE--------------------\n");
                else
                        PJK_UT_MSG("------------------TIMEDOUT--------------------\n");
        }



        /*
        PJK_UT_MSG("LNetEQWait()\n");
        rc = LNetEQWait(eqh,&ev);
        if(rc != 0)
                goto exit5;
        */

exit5:
        PJK_UT_MSG("LNetMDUnlink()\n");
        LNetMDUnlink(mdh);

        if(!seen_unlink){
                PJK_UT_MSG("------------Waiting for UNLINK ------------\n");
                i=0;
                while(i++ < 120 && seen_unlink == 0)
                        cfs_pause(cfs_time_seconds(1));
        }

        cfs_pause(cfs_time_seconds(1));
exit4:
        PJK_UT_MSG("LNetEQFree()\n");
        LNetEQFree(eqh);
exit1:
        PJK_UT_MSG("LNetNiFini()\n");
        LNetNIFini();
exit0:
        if(buffer)
                LIBCFS_FREE(buffer,pkt_size);

        return -1;
} /* utcli_init() */


static void /*__exit*/ utcli_cleanup(void)
{
        PJK_UT_MSG(">>>\n");
        PJK_UT_MSG("<<<\n");
} /* utcli_cleanup() */


MODULE_AUTHOR("PJ Kirner (CFS)");
MODULE_DESCRIPTION("A simple LNET Unit Test module");
MODULE_LICENSE("GPL");

cfs_module(ut_cli, "1.0.0", utcli_init, utcli_cleanup);
