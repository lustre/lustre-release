/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */


#define UT_MSG_MODULE_NAME "utsrv "
#include "ut.h"


int pkt_size = 300;
module_param(pkt_size,int,S_IRUGO);
int auto_unlink=1;
module_param(auto_unlink,int,S_IRUGO);

char                   *buffer = 0;
lnet_handle_eq_t        eqh;
lnet_handle_me_t        meh;
lnet_handle_md_t        mdh;

static int __init utsrv_init(void)
{
        int                     rc;
        lnet_process_id_t       anypid;
        lnet_process_id_t       mypid;
        lnet_md_t               md;

        PJK_UT_MSG(">>>\n");
        PJK_UT_MSG("pkt_size=%d\n",pkt_size);
        PJK_UT_MSG("auto_unlink=%d\n",auto_unlink);

        PJK_UT_MSG("LIBCFS_ALLOC\n");
        LIBCFS_ALLOC (buffer, pkt_size);
        if (buffer == NULL)
        {
                CERROR ("Unable to allocate out_buf (%d bytes)\n", pkt_size);
                rc = -ENOMEM;
                goto exit0;
        }

        PJK_UT_MSG("LNetNiInit()\n");
        rc = LNetNIInit(0);
        if (rc < 0)
        {
                CERROR ("LNetNIInit: error %d\n", rc);
                goto exit1;
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
                goto exit2;
        }

        anypid.nid = LNET_NID_ANY;
        anypid.pid = LNET_PID_ANY;


        PJK_UT_MSG("LNetMEAttach\n");
        rc = LNetMEAttach(
                UT_PORTAL,    /* ptl index*/
                anypid,       /* pid - in this case allow any*/
                0,            /*matchbits*/
                0x0FFFF,      /*ignorebits - ignore botton 16-bits*/
                LNET_UNLINK,  /* unlik vs LNET_RETAIN*/
                LNET_INS_BEFORE,
                &meh);
        if(rc != 0) {
                CERROR("LNetMeAttach failed %d\n",rc);
                goto exit3;
        }

        md.start = buffer;
        md.length = pkt_size;
        md.threshold = auto_unlink ? 1 : 100;
        md.max_size = 0;
        md.options = 0;
        md.options |= LNET_MD_OP_GET;
        md.options |= LNET_MD_OP_PUT;
        md.options |= LNET_MD_ACK_DISABLE;
        md.user_ptr= 0;
        md.eq_handle = eqh;

        PJK_UT_MSG("LNetMDAttach\n");
        rc = LNetMDAttach(
                meh,
                md,
                LNET_UNLINK,
                &mdh);
        if(rc != 0){
                CERROR("LNetMDAttach failed %d\n",rc);
                goto exit4;
        }

        rc = 0;
        goto exit0;

exit4:
        PJK_UT_MSG("LNetMEUnlink()\n");
        LNetMEUnlink(meh);
exit3:
        PJK_UT_MSG("LNetEQFree()\n");
        LNetEQFree(eqh);
exit2:
        PJK_UT_MSG("LNetNiFini()\n");
        LNetNIFini();
exit1:
        LIBCFS_FREE(buffer,pkt_size);
exit0:
        PJK_UT_MSG("<<< rc=%d\n",rc);
        return rc;

} /* utsrv_init() */


static void /*__exit*/ utsrv_cleanup(void)
{
        PJK_UT_MSG(">>>\n");
        PJK_UT_MSG("LNetMDUnlink()\n");
        LNetMDUnlink(mdh);
        PJK_UT_MSG("LNetMEUnlink()\n");
        LNetMEUnlink(meh);
        PJK_UT_MSG("LNetEQFree()\n");
        LNetEQFree(eqh);
        PJK_UT_MSG("LNetNiFini()\n");
        LNetNIFini();
        LIBCFS_FREE(buffer,pkt_size);
        PJK_UT_MSG("<<<\n");
} /* utsrv_cleanup() */


MODULE_AUTHOR("PJ Kirner (CFS)");
MODULE_DESCRIPTION("A simple LNET Unit Test module");
MODULE_LICENSE("GPL");

cfs_module(utsvr, "1.0.0", utsrv_init, utsrv_cleanup);

