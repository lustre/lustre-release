/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/iiblnd/iiblnd.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "iiblnd.h"

lnd_t the_kiblnd = {
        .lnd_type          = IIBLND,
        .lnd_startup       = kibnal_startup,
        .lnd_shutdown      = kibnal_shutdown,
        .lnd_ctl           = kibnal_ctl,
        .lnd_send          = kibnal_send,
        .lnd_recv          = kibnal_recv,
        .lnd_eager_recv    = kibnal_eager_recv,
};

kib_data_t              kibnal_data;

__u32 
kibnal_cksum (void *ptr, int nob)
{
        char  *c  = ptr;
        __u32  sum = 0;

        while (nob-- > 0)
                sum = ((sum << 1) | (sum >> 31)) + *c++;
        
        /* ensure I don't return 0 (== no checksum) */
        return (sum == 0) ? 1 : sum;
}

void
kibnal_init_msg(kib_msg_t *msg, int type, int body_nob)
{
        msg->ibm_type = type;
        msg->ibm_nob  = offsetof(kib_msg_t, ibm_u) + body_nob;
}

void
kibnal_pack_msg(kib_msg_t *msg, __u32 version, int credits, 
                lnet_nid_t dstnid, __u64 dststamp, __u64 seq)
{
        /* CAVEAT EMPTOR! all message fields not set here should have been
         * initialised previously. */
        msg->ibm_magic    = IBNAL_MSG_MAGIC;
        msg->ibm_version  = version;
        /*   ibm_type */
        msg->ibm_credits  = credits;
        /*   ibm_nob */
        msg->ibm_cksum    = 0;
        msg->ibm_srcnid   = kibnal_data.kib_ni->ni_nid;
        msg->ibm_srcstamp = kibnal_data.kib_incarnation;
        msg->ibm_dstnid   = dstnid;
        msg->ibm_dststamp = dststamp;
        msg->ibm_seq      = seq;

        if (*kibnal_tunables.kib_cksum) {
                /* NB ibm_cksum zero while computing cksum */
                msg->ibm_cksum = kibnal_cksum(msg, msg->ibm_nob);
        }
}

void
kibnal_pack_connmsg(kib_msg_t *msg, __u32 version, int nob, 
                    int type, lnet_nid_t dstnid, __u64 dststamp)
{
        LASSERT (nob >= offsetof(kib_msg_t, ibm_u) + sizeof(kib_connparams_t));

        memset(msg, 0, nob);
        kibnal_init_msg(msg, type, sizeof(kib_connparams_t));

        msg->ibm_u.connparams.ibcp_queue_depth = IBNAL_MSG_QUEUE_SIZE;
        msg->ibm_u.connparams.ibcp_max_msg_size = IBNAL_MSG_SIZE;
        msg->ibm_u.connparams.ibcp_max_frags = IBNAL_MAX_RDMA_FRAGS;

        kibnal_pack_msg(msg, version, 0, dstnid, dststamp, 0);
}

int
kibnal_unpack_msg(kib_msg_t *msg, __u32 expected_version, int nob)
{
        const int hdr_size = offsetof(kib_msg_t, ibm_u);
        __u32     msg_cksum;
        __u32     msg_version;
        int       flip;
        int       msg_nob;
#if !IBNAL_USE_FMR
        int       i;
        int       n;
#endif
        /* 6 bytes are enough to have received magic + version */
        if (nob < 6) {
                CERROR("Short message: %d\n", nob);
                return -EPROTO;
        }

        /* Future protocol version compatibility support!
         * If the iiblnd-specific protocol changes, or when LNET unifies
         * protocols over all LNDs, the initial connection will negotiate a
         * protocol version.  If I find this, I avoid any console errors.  If
         * my is doing connection establishment, the reject will tell the peer
         * which version I'm running. */

        if (msg->ibm_magic == IBNAL_MSG_MAGIC) {
                flip = 0;
        } else if (msg->ibm_magic == __swab32(IBNAL_MSG_MAGIC)) {
                flip = 1;
        } else {
                if (msg->ibm_magic == LNET_PROTO_MAGIC ||
                    msg->ibm_magic == __swab32(LNET_PROTO_MAGIC))
                        return -EPROTO;

                /* Completely out to lunch */
                CERROR("Bad magic: %08x\n", msg->ibm_magic);
                return -EPROTO;
        }

        msg_version = flip ? __swab16(msg->ibm_version) : msg->ibm_version;
        if (expected_version == 0) {
                if (msg_version != IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD &&
                    msg_version != IBNAL_MSG_VERSION)
                        return -EPROTO;
        } else if (msg_version != expected_version) {
                CERROR("Bad version: %x(%x expected)\n", 
                       msg_version, expected_version);
                return -EPROTO;
        }

        if (nob < hdr_size) {
                CERROR("Short message: %d\n", nob);
                return -EPROTO;
        }

        msg_nob = flip ? __swab32(msg->ibm_nob) : msg->ibm_nob;
        if (msg_nob > nob) {
                CERROR("Short message: got %d, wanted %d\n", nob, msg_nob);
                return -EPROTO;
        }

        /* checksum must be computed with ibm_cksum zero and BEFORE anything
         * gets flipped */
        msg_cksum = flip ? __swab32(msg->ibm_cksum) : msg->ibm_cksum;
        msg->ibm_cksum = 0;
        if (msg_cksum != 0 &&
            msg_cksum != kibnal_cksum(msg, msg_nob)) {
                CERROR("Bad checksum\n");
                return -EPROTO;
        }
        msg->ibm_cksum = msg_cksum;
        
        if (flip) {
                /* leave magic unflipped as a clue to peer endianness */
                msg->ibm_version = msg_version;
                CLASSERT (sizeof(msg->ibm_type) == 1);
                CLASSERT (sizeof(msg->ibm_credits) == 1);
                msg->ibm_nob = msg_nob;
                __swab64s(&msg->ibm_srcnid);
                __swab64s(&msg->ibm_srcstamp);
                __swab64s(&msg->ibm_dstnid);
                __swab64s(&msg->ibm_dststamp);
                __swab64s(&msg->ibm_seq);
        }
        
        if (msg->ibm_srcnid == LNET_NID_ANY) {
                CERROR("Bad src nid: %s\n", libcfs_nid2str(msg->ibm_srcnid));
                return -EPROTO;
        }

        switch (msg->ibm_type) {
        default:
                CERROR("Unknown message type %x\n", msg->ibm_type);
                return -EPROTO;
                
        case IBNAL_MSG_NOOP:
                break;

        case IBNAL_MSG_IMMEDIATE:
                if (msg_nob < offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[0])) {
                        CERROR("Short IMMEDIATE: %d(%d)\n", msg_nob,
                               (int)offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[0]));
                        return -EPROTO;
                }
                break;

        case IBNAL_MSG_PUT_REQ:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.putreq)) {
                        CERROR("Short PUT_REQ: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.putreq)));
                        return -EPROTO;
                }
                break;

        case IBNAL_MSG_PUT_ACK:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.putack)) {
                        CERROR("Short PUT_ACK: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.putack)));
                        return -EPROTO;
                }
#if IBNAL_USE_FMR
                if (flip) {
                        __swab64s(&msg->ibm_u.putack.ibpam_rd.rd_addr);
                        __swab32s(&msg->ibm_u.putack.ibpam_rd.rd_nob);
                        __swab32s(&msg->ibm_u.putack.ibpam_rd.rd_key);
                }
#else
                if (flip) {
                        __swab32s(&msg->ibm_u.putack.ibpam_rd.rd_key);
                        __swab32s(&msg->ibm_u.putack.ibpam_rd.rd_nfrag);
                }
                
                n = msg->ibm_u.putack.ibpam_rd.rd_nfrag;
                if (n <= 0 || n > IBNAL_MAX_RDMA_FRAGS) {
                        CERROR("Bad PUT_ACK nfrags: %d, should be 0 < n <= %d\n", 
                               n, IBNAL_MAX_RDMA_FRAGS);
                        return -EPROTO;
                }
                
                if (msg_nob < offsetof(kib_msg_t, ibm_u.putack.ibpam_rd.rd_frags[n])) {
                        CERROR("Short PUT_ACK: %d(%d)\n", msg_nob,
                               (int)offsetof(kib_msg_t, ibm_u.putack.ibpam_rd.rd_frags[n]));
                        return -EPROTO;
                }

                if (flip) {
                        for (i = 0; i < n; i++) {
                                __swab32s(&msg->ibm_u.putack.ibpam_rd.rd_frags[i].rf_nob);
                                __swab64s(&msg->ibm_u.putack.ibpam_rd.rd_frags[i].rf_addr);
                        }
                }
#endif
                break;

        case IBNAL_MSG_GET_REQ:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.get)) {
                        CERROR("Short GET_REQ: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.get)));
                        return -EPROTO;
                }
#if IBNAL_USE_FMR
                if (flip) {
                        __swab64s(&msg->ibm_u.get.ibgm_rd.rd_addr);
                        __swab32s(&msg->ibm_u.get.ibgm_rd.rd_nob);
                        __swab32s(&msg->ibm_u.get.ibgm_rd.rd_key);
                }
#else                
                if (flip) {
                        __swab32s(&msg->ibm_u.get.ibgm_rd.rd_key);
                        __swab32s(&msg->ibm_u.get.ibgm_rd.rd_nfrag);
                }

                n = msg->ibm_u.get.ibgm_rd.rd_nfrag;
                if (n <= 0 || n > IBNAL_MAX_RDMA_FRAGS) {
                        CERROR("Bad GET_REQ nfrags: %d, should be 0 < n <= %d\n", 
                               n, IBNAL_MAX_RDMA_FRAGS);
                        return -EPROTO;
                }
                
                if (msg_nob < offsetof(kib_msg_t, ibm_u.get.ibgm_rd.rd_frags[n])) {
                        CERROR("Short GET_REQ: %d(%d)\n", msg_nob,
                               (int)offsetof(kib_msg_t, ibm_u.get.ibgm_rd.rd_frags[n]));
                        return -EPROTO;
                }
                
                if (flip)
                        for (i = 0; i < msg->ibm_u.get.ibgm_rd.rd_nfrag; i++) {
                                __swab32s(&msg->ibm_u.get.ibgm_rd.rd_frags[i].rf_nob);
                                __swab64s(&msg->ibm_u.get.ibgm_rd.rd_frags[i].rf_addr);
                        }
#endif
                break;

        case IBNAL_MSG_PUT_NAK:
        case IBNAL_MSG_PUT_DONE:
        case IBNAL_MSG_GET_DONE:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.completion)) {
                        CERROR("Short RDMA completion: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.completion)));
                        return -EPROTO;
                }
                if (flip)
                        __swab32s(&msg->ibm_u.completion.ibcm_status);
                break;

        case IBNAL_MSG_CONNREQ:
        case IBNAL_MSG_CONNACK:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.connparams)) {
                        CERROR("Short connreq/ack: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.connparams)));
                        return -EPROTO;
                }
                if (flip) {
                        __swab32s(&msg->ibm_u.connparams.ibcp_queue_depth);
                        __swab32s(&msg->ibm_u.connparams.ibcp_max_msg_size);
                        __swab32s(&msg->ibm_u.connparams.ibcp_max_frags);
                }
                break;
        }
        return 0;
}

IB_HANDLE
kibnal_create_cep(lnet_nid_t nid)
{
        FSTATUS        frc;
        __u32          u32val;
        IB_HANDLE      cep;

        cep = iba_cm_create_cep(CM_RC_TYPE);
        if (cep == NULL) {
                CERROR ("Can't create CEP for %s\n",
                        (nid == LNET_NID_ANY) ? "listener" :
                        libcfs_nid2str(nid));
                return NULL;
        }

        if (nid == LNET_NID_ANY) {
                u32val = 1;
                frc = iba_cm_modify_cep(cep, CM_FLAG_ASYNC_ACCEPT,
                                        (char *)&u32val, sizeof(u32val), 0);
                if (frc != FSUCCESS) {
                        CERROR("Can't set async_accept: %d\n", frc);
                        goto failed;
                }

                u32val = 0;                     /* sets system max */
                frc = iba_cm_modify_cep(cep, CM_FLAG_LISTEN_BACKLOG,
                                        (char *)&u32val, sizeof(u32val), 0);
                if (frc != FSUCCESS) {
                        CERROR("Can't set listen backlog: %d\n", frc);
                        goto failed;
                }
        }
        
        u32val = 1;
        frc = iba_cm_modify_cep(cep, CM_FLAG_TIMEWAIT_CALLBACK,
                                (char *)&u32val, sizeof(u32val), 0);
        if (frc != FSUCCESS) {
                CERROR("Can't set timewait_callback for %s: %d\n", 
                        (nid == LNET_NID_ANY) ? "listener" :
                        libcfs_nid2str(nid), frc);
                goto failed;
        }

        return cep;
        
 failed:
        iba_cm_destroy_cep(cep);
        return NULL;
}

#define IBNAL_CHECK_ADVERT 1
#if IBNAL_CHECK_ADVERT
void
kibnal_service_query_done (void *arg, QUERY *qry, 
                           QUERY_RESULT_VALUES *qry_result)
{
        int                    *rcp = arg;
        FSTATUS                 frc = qry_result->Status;
        SERVICE_RECORD_RESULTS *svc_rslt;
        IB_SERVICE_RECORD      *svc;
        lnet_nid_t              nid;

        if (frc != FSUCCESS || qry_result->ResultDataSize == 0) {
                CERROR("Error checking advert: status %d data size %d\n",
                       frc, qry_result->ResultDataSize);
                *rcp = -EIO;
                goto out;
        }

        svc_rslt = (SERVICE_RECORD_RESULTS *)qry_result->QueryResult;

        if (svc_rslt->NumServiceRecords < 1) {
                CERROR("Check advert: %d records\n",
                       svc_rslt->NumServiceRecords);
                *rcp = -ENOENT;
                goto out;
        }

        svc = &svc_rslt->ServiceRecords[0];
        nid = le64_to_cpu(*kibnal_service_nid_field(svc));
        
        CDEBUG(D_NET, "Check advert: %s "LPX64" "LPX64":%04x\n",
               libcfs_nid2str(nid), svc->RID.ServiceID, 
               svc->RID.ServiceGID.Type.Global.InterfaceID, 
               svc->RID.ServiceP_Key);

        if (nid != kibnal_data.kib_ni->ni_nid) {
                CERROR("Check advert: Bad NID %s (%s expected)\n",
                       libcfs_nid2str(nid),
                       libcfs_nid2str(kibnal_data.kib_ni->ni_nid));
                *rcp = -EINVAL;
                goto out;
        }

        if (svc->RID.ServiceID != *kibnal_tunables.kib_service_number) {
                CERROR("Check advert: Bad ServiceID "LPX64" (%x expected)\n",
                       svc->RID.ServiceID,
                       *kibnal_tunables.kib_service_number);
                *rcp = -EINVAL;
                goto out;
        }

        if (svc->RID.ServiceGID.Type.Global.InterfaceID != 
            kibnal_data.kib_port_guid) {
                CERROR("Check advert: Bad GUID "LPX64" ("LPX64" expected)\n",
                       svc->RID.ServiceGID.Type.Global.InterfaceID,
                       kibnal_data.kib_port_guid);
                *rcp = -EINVAL;
                goto out;
        }

        if (svc->RID.ServiceP_Key != kibnal_data.kib_port_pkey) {
                CERROR("Check advert: Bad PKEY %04x (%04x expected)\n",
                       svc->RID.ServiceP_Key, kibnal_data.kib_port_pkey);
                *rcp = -EINVAL;
                goto out;
        }

        CDEBUG(D_NET, "Check advert OK\n");
        *rcp = 0;
                
 out:
        up (&kibnal_data.kib_listener_signal);                
}

int
kibnal_check_advert (void)
{
        /* single-threaded */
        static QUERY               qry;

        FSTATUS                    frc;
        int                        rc;

        memset (&qry, 0, sizeof(qry));
        qry.InputType = InputTypeServiceRecord;
        qry.OutputType = OutputTypeServiceRecord;
        kibnal_set_service_keys(&qry.InputValue.ServiceRecordValue.ServiceRecord,
                                kibnal_data.kib_ni->ni_nid);
        qry.InputValue.ServiceRecordValue.ComponentMask = KIBNAL_SERVICE_KEY_MASK;

        frc = iba_sd_query_port_fabric_info(kibnal_data.kib_sd, 
                                            kibnal_data.kib_port_guid,
                                            &qry, 
                                            kibnal_service_query_done,
                                            &kibnal_data.kib_sdretry, 
                                            &rc);
        if (frc != FPENDING) {
                CERROR ("Immediate error %d checking SM service\n", frc);
                return -EIO;
        }
        
        down (&kibnal_data.kib_listener_signal);
        
        if (rc != 0)
                CERROR ("Error %d checking SM service\n", rc);
        return rc;
}
#else
int
kibnal_check_advert(void)
{
        return 0;
}
#endif

void 
kibnal_fill_fod(FABRIC_OPERATION_DATA *fod, FABRIC_OPERATION_TYPE type)
{
        IB_SERVICE_RECORD     *svc;

        memset (fod, 0, sizeof(*fod));
        fod->Type = type;

        svc = &fod->Value.ServiceRecordValue.ServiceRecord;
        svc->RID.ServiceID = *kibnal_tunables.kib_service_number;
        svc->RID.ServiceGID.Type.Global.InterfaceID = kibnal_data.kib_port_guid;
        svc->RID.ServiceGID.Type.Global.SubnetPrefix = DEFAULT_SUBNET_PREFIX;
        svc->RID.ServiceP_Key = kibnal_data.kib_port_pkey;
        svc->ServiceLease = 0xffffffff;

        kibnal_set_service_keys(svc, kibnal_data.kib_ni->ni_nid);
}

void
kibnal_service_setunset_done (void *arg, FABRIC_OPERATION_DATA *fod,
                              FSTATUS frc, uint32 madrc)
{
        *(FSTATUS *)arg = frc;
        up (&kibnal_data.kib_listener_signal);
}

int
kibnal_advertise (void)
{
        /* Single threaded here */
        static FABRIC_OPERATION_DATA fod;

        IB_SERVICE_RECORD *svc = &fod.Value.ServiceRecordValue.ServiceRecord;
        FSTATUS            frc;
        FSTATUS            frc2;

        if (strlen(*kibnal_tunables.kib_service_name) >=
            sizeof(svc->ServiceName)) {
                CERROR("Service name '%s' too long (%d chars max)\n",
                       *kibnal_tunables.kib_service_name,
                       (int)sizeof(svc->ServiceName) - 1);
                return -EINVAL;
        }

        kibnal_fill_fod(&fod, FabOpSetServiceRecord);

        CDEBUG(D_NET, "Advertising service id "LPX64" %s:%s\n", 
               svc->RID.ServiceID, svc->ServiceName, 
               libcfs_nid2str(le64_to_cpu(*kibnal_service_nid_field(svc))));

        frc = iba_sd_port_fabric_operation(kibnal_data.kib_sd,
                                           kibnal_data.kib_port_guid,
                                           &fod, 
                                           kibnal_service_setunset_done, 
                                           &kibnal_data.kib_sdretry,
                                           &frc2);

        if (frc != FSUCCESS && frc != FPENDING) {
                CERROR ("Immediate error %d advertising NID %s\n",
                        frc, libcfs_nid2str(kibnal_data.kib_ni->ni_nid));
                return -EIO;
        }

        down (&kibnal_data.kib_listener_signal);

        frc = frc2;
        if (frc == FSUCCESS)
                return 0;
        
        CERROR ("Error %d advertising %s\n",
                frc, libcfs_nid2str(kibnal_data.kib_ni->ni_nid));
        return -EIO;
}

void
kibnal_unadvertise (int expect_success)
{
        /* single threaded */
        static FABRIC_OPERATION_DATA fod;

        IB_SERVICE_RECORD *svc = &fod.Value.ServiceRecordValue.ServiceRecord;
        FSTATUS            frc;
        FSTATUS            frc2;

        LASSERT (kibnal_data.kib_ni->ni_nid != LNET_NID_ANY);

        kibnal_fill_fod(&fod, FabOpDeleteServiceRecord);

        CDEBUG(D_NET, "Unadvertising service %s:%s\n",
               svc->ServiceName, 
               libcfs_nid2str(le64_to_cpu(*kibnal_service_nid_field(svc))));
        
        frc = iba_sd_port_fabric_operation(kibnal_data.kib_sd,
                                           kibnal_data.kib_port_guid,
                                           &fod, 
                                           kibnal_service_setunset_done, 
                                           &kibnal_data.kib_sdretry, 
                                           &frc2);
        if (frc != FSUCCESS && frc != FPENDING) {
                CERROR ("Immediate error %d unadvertising NID %s\n",
                        frc, libcfs_nid2str(kibnal_data.kib_ni->ni_nid));
                return;
        }

        down (&kibnal_data.kib_listener_signal);

        CDEBUG(D_NET, "Unadvertise rc: %d\n", frc2);

        if ((frc2 == FSUCCESS) == !!expect_success)
                return;

        if (expect_success)
                CERROR("Error %d unadvertising NID %s\n",
                       frc2, libcfs_nid2str(kibnal_data.kib_ni->ni_nid));
        else
                CWARN("Removed conflicting NID %s\n",
                      libcfs_nid2str(kibnal_data.kib_ni->ni_nid));
}

void
kibnal_stop_listener(int normal_shutdown)
{
        /* NB this also disables peer creation and destroys all existing
         * peers */
        IB_HANDLE      cep = kibnal_data.kib_listener_cep;
        unsigned long  flags;
        FSTATUS        frc;

        LASSERT (cep != NULL);

        kibnal_unadvertise(normal_shutdown);

        frc = iba_cm_cancel(cep);
        if (frc != FSUCCESS && frc != FPENDING)
                CERROR ("Error %d stopping listener\n", frc);

        down(&kibnal_data.kib_listener_signal);

        frc = iba_cm_destroy_cep(cep);
        if (frc != FSUCCESS)
                CERROR ("Error %d destroying listener CEP\n", frc);

        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
        /* This assignment disables peer creation */
        kibnal_data.kib_listener_cep = NULL;
        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        /* Start to tear down any peers created while the listener was
         * running */
        kibnal_del_peer(LNET_NID_ANY);
}

int
kibnal_start_listener(void)
{
        /* NB this also enables peer creation */

        IB_HANDLE      cep;
        CM_LISTEN_INFO info;
        unsigned long  flags;
        int            rc;
        FSTATUS        frc;

        LASSERT (kibnal_data.kib_listener_cep == NULL);
        init_MUTEX_LOCKED (&kibnal_data.kib_listener_signal);

        cep = kibnal_create_cep(LNET_NID_ANY);
        if (cep == NULL)
                return -ENOMEM;

        memset (&info, 0, sizeof(info));
        info.ListenAddr.EndPt.SID = *kibnal_tunables.kib_service_number;

        frc = iba_cm_listen(cep, &info, kibnal_listen_callback, NULL);
        if (frc != FSUCCESS && frc != FPENDING) {
                CERROR ("iba_cm_listen error: %d\n", frc);

                iba_cm_destroy_cep(cep);
                return -EIO;
        }

        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
        /* This assignment enables peer creation */
        kibnal_data.kib_listener_cep = cep;
        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        rc = kibnal_advertise();
        if (rc == 0)
                rc = kibnal_check_advert();

        if (rc == 0)
                return 0;

        kibnal_stop_listener(0);
        return rc;
}

int
kibnal_create_peer (kib_peer_t **peerp, lnet_nid_t nid)
{
        kib_peer_t    *peer;
        unsigned long  flags;
        int            rc;

        LASSERT (nid != LNET_NID_ANY);

        LIBCFS_ALLOC (peer, sizeof (*peer));
        if (peer == NULL) {
                CERROR("Cannot allocate peer\n");
                return -ENOMEM;
        }

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        peer->ibp_nid = nid;
        atomic_set (&peer->ibp_refcount, 1);    /* 1 ref for caller */

        INIT_LIST_HEAD (&peer->ibp_list);       /* not in the peer table yet */
        INIT_LIST_HEAD (&peer->ibp_conns);
        INIT_LIST_HEAD (&peer->ibp_tx_queue);

        peer->ibp_error = 0;
        peer->ibp_last_alive = cfs_time_current();
        peer->ibp_reconnect_interval = 0;       /* OK to connect at any time */

        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
        
        if (atomic_read(&kibnal_data.kib_npeers) >=
            *kibnal_tunables.kib_concurrent_peers) {
                rc = -EOVERFLOW;        /* !! but at least it distinguishes */
        } else if (kibnal_data.kib_listener_cep == NULL) {
                rc = -ESHUTDOWN;        /* shutdown has started */
        } else {
                rc = 0;
                /* npeers only grows with the global lock held */
                atomic_inc(&kibnal_data.kib_npeers);
        }
        
        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        if (rc != 0) {
                CERROR("Can't create peer: %s\n", 
                       (rc == -ESHUTDOWN) ? "shutting down" : 
                       "too many peers");
                LIBCFS_FREE(peer, sizeof(*peer));
        } else {
                *peerp = peer;
        }
        
        return rc;
}

void
kibnal_destroy_peer (kib_peer_t *peer)
{

        LASSERT (atomic_read (&peer->ibp_refcount) == 0);
        LASSERT (peer->ibp_persistence == 0);
        LASSERT (!kibnal_peer_active(peer));
        LASSERT (!kibnal_peer_connecting(peer));
        LASSERT (list_empty (&peer->ibp_conns));
        LASSERT (list_empty (&peer->ibp_tx_queue));

        LIBCFS_FREE (peer, sizeof (*peer));

        /* NB a peer's connections keep a reference on their peer until
         * they are destroyed, so we can be assured that _all_ state to do
         * with this peer has been cleaned up when its refcount drops to
         * zero. */
        atomic_dec (&kibnal_data.kib_npeers);
}

/* the caller is responsible for accounting for the additional reference
 * that this creates */
kib_peer_t *
kibnal_find_peer_locked (lnet_nid_t nid)
{
        struct list_head *peer_list = kibnal_nid2peerlist (nid);
        struct list_head *tmp;
        kib_peer_t       *peer;

        list_for_each (tmp, peer_list) {

                peer = list_entry (tmp, kib_peer_t, ibp_list);

                LASSERT (peer->ibp_persistence != 0 ||
                         kibnal_peer_connecting(peer) ||
                         !list_empty (&peer->ibp_conns));

                if (peer->ibp_nid != nid)
                        continue;

                CDEBUG(D_NET, "got peer %s (%d)\n",
                       libcfs_nid2str(nid), atomic_read (&peer->ibp_refcount));
                return (peer);
        }
        return (NULL);
}

void
kibnal_unlink_peer_locked (kib_peer_t *peer)
{
        LASSERT (peer->ibp_persistence == 0);
        LASSERT (list_empty(&peer->ibp_conns));

        LASSERT (kibnal_peer_active(peer));
        list_del_init (&peer->ibp_list);
        /* lose peerlist's ref */
        kibnal_peer_decref(peer);
}

int
kibnal_get_peer_info (int index, lnet_nid_t *nidp, int *persistencep)
{
        kib_peer_t        *peer;
        struct list_head  *ptmp;
        unsigned long      flags;
        int                i;

        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++) {

                list_for_each (ptmp, &kibnal_data.kib_peers[i]) {

                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 kibnal_peer_connecting(peer) ||
                                 !list_empty (&peer->ibp_conns));

                        if (index-- > 0)
                                continue;

                        *nidp = peer->ibp_nid;
                        *persistencep = peer->ibp_persistence;

                        read_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                               flags);
                        return (0);
                }
        }

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
        return (-ENOENT);
}

int
kibnal_add_persistent_peer (lnet_nid_t nid)
{
        unsigned long      flags;
        kib_peer_t        *peer;
        kib_peer_t        *peer2;
        int                rc;
        
        if (nid == LNET_NID_ANY)
                return (-EINVAL);

        rc = kibnal_create_peer(&peer, nid);
        if (rc != 0)
                return rc;

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        /* I'm always called with a reference on kibnal_data.kib_ni
         * so shutdown can't have started */
        LASSERT (kibnal_data.kib_listener_cep != NULL);

        peer2 = kibnal_find_peer_locked (nid);
        if (peer2 != NULL) {
                kibnal_peer_decref (peer);
                peer = peer2;
        } else {
                /* peer table takes existing ref on peer */
                list_add_tail (&peer->ibp_list,
                               kibnal_nid2peerlist (nid));
        }

        peer->ibp_persistence++;
        
        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);
        return (0);
}

void
kibnal_del_peer_locked (kib_peer_t *peer)
{
        struct list_head *ctmp;
        struct list_head *cnxt;
        kib_conn_t       *conn;

        peer->ibp_persistence = 0;

        if (list_empty(&peer->ibp_conns)) {
                kibnal_unlink_peer_locked(peer);
        } else {
                list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                        conn = list_entry(ctmp, kib_conn_t, ibc_list);

                        kibnal_close_conn_locked (conn, 0);
                }
                /* NB peer is no longer persistent; closing its last conn
                 * unlinked it. */
        }
        /* NB peer now unlinked; might even be freed if the peer table had the
         * last ref on it. */
}

int
kibnal_del_peer (lnet_nid_t nid)
{
        unsigned long      flags;
        CFS_LIST_HEAD     (zombies);
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        kib_peer_t        *peer;
        int                lo;
        int                hi;
        int                i;
        int                rc = -ENOENT;

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        if (nid != LNET_NID_ANY)
                lo = hi = kibnal_nid2peerlist(nid) - kibnal_data.kib_peers;
        else {
                lo = 0;
                hi = kibnal_data.kib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kibnal_data.kib_peers[i]) {
                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 kibnal_peer_connecting(peer) ||
                                 !list_empty (&peer->ibp_conns));

                        if (!(nid == LNET_NID_ANY || peer->ibp_nid == nid))
                                continue;

                        if (!list_empty(&peer->ibp_tx_queue)) {
                                LASSERT (list_empty(&peer->ibp_conns));

                                list_splice_init(&peer->ibp_tx_queue, &zombies);
                        }

                        kibnal_del_peer_locked (peer);
                        rc = 0;         /* matched something */
                }
        }

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        kibnal_txlist_done(&zombies, -EIO);

        return (rc);
}

kib_conn_t *
kibnal_get_conn_by_idx (int index)
{
        kib_peer_t        *peer;
        struct list_head  *ptmp;
        kib_conn_t        *conn;
        struct list_head  *ctmp;
        unsigned long      flags;
        int                i;

        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++) {
                list_for_each (ptmp, &kibnal_data.kib_peers[i]) {

                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 kibnal_peer_connecting(peer) ||
                                 !list_empty (&peer->ibp_conns));

                        list_for_each (ctmp, &peer->ibp_conns) {
                                if (index-- > 0)
                                        continue;

                                conn = list_entry (ctmp, kib_conn_t, ibc_list);
                                kibnal_conn_addref(conn);
                                read_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                                       flags);
                                return (conn);
                        }
                }
        }

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
        return (NULL);
}

int
kibnal_conn_rts(kib_conn_t *conn, 
                __u32 qpn, __u8 resp_res, __u8 init_depth, __u32 psn)
{
        IB_PATH_RECORD         *path = &conn->ibc_cvars->cv_path;
        IB_HANDLE               qp = conn->ibc_qp;
        IB_QP_ATTRIBUTES_MODIFY modify_attr;
        FSTATUS                 frc;
        int                     rc;

        if (resp_res > kibnal_data.kib_hca_attrs.MaxQPResponderResources)
                resp_res = kibnal_data.kib_hca_attrs.MaxQPResponderResources;

        if (init_depth > kibnal_data.kib_hca_attrs.MaxQPInitiatorDepth)
                init_depth = kibnal_data.kib_hca_attrs.MaxQPInitiatorDepth;

        modify_attr = (IB_QP_ATTRIBUTES_MODIFY) {
                .RequestState       = QPStateReadyToRecv,
                .RecvPSN            = IBNAL_STARTING_PSN,
                .DestQPNumber       = qpn,
                .ResponderResources = resp_res,
                .MinRnrTimer        = UsecToRnrNakTimer(2000), /* 20 ms */
                .Attrs              = (IB_QP_ATTR_RECVPSN |
                                       IB_QP_ATTR_DESTQPNUMBER | 
                                       IB_QP_ATTR_RESPONDERRESOURCES | 
                                       IB_QP_ATTR_DESTAV | 
                                       IB_QP_ATTR_PATHMTU | 
                                       IB_QP_ATTR_MINRNRTIMER),
        };
        GetAVFromPath(0, path, &modify_attr.PathMTU, NULL, 
                      &modify_attr.DestAV);

        frc = iba_modify_qp(qp, &modify_attr, NULL);
        if (frc != FSUCCESS) {
                CERROR("Can't set QP %s ready to receive: %d\n",
                       libcfs_nid2str(conn->ibc_peer->ibp_nid), frc);
                return -EIO;
        }

        rc = kibnal_post_receives(conn);
        if (rc != 0) {
                CERROR("Can't post receives for %s: %d\n",
                       libcfs_nid2str(conn->ibc_peer->ibp_nid), rc);
                return rc;
        }

        modify_attr = (IB_QP_ATTRIBUTES_MODIFY) {
                .RequestState           = QPStateReadyToSend,
                .FlowControl            = TRUE,
                .InitiatorDepth         = init_depth,
                .SendPSN                = psn,
                .LocalAckTimeout        = path->PktLifeTime + 2, /* 2 or 1? */
                .RetryCount             = IBNAL_RETRY,
                .RnrRetryCount          = IBNAL_RNR_RETRY,
                .Attrs                  = (IB_QP_ATTR_FLOWCONTROL | 
                                           IB_QP_ATTR_INITIATORDEPTH | 
                                           IB_QP_ATTR_SENDPSN | 
                                           IB_QP_ATTR_LOCALACKTIMEOUT | 
                                           IB_QP_ATTR_RETRYCOUNT | 
                                           IB_QP_ATTR_RNRRETRYCOUNT),
        };

        frc = iba_modify_qp(qp, &modify_attr, NULL);
        if (frc != FSUCCESS) {
                CERROR("Can't set QP %s ready to send: %d\n",
                       libcfs_nid2str(conn->ibc_peer->ibp_nid), frc);
                return -EIO;
        }

        frc = iba_query_qp(conn->ibc_qp, &conn->ibc_cvars->cv_qpattrs, NULL);
        if (frc != FSUCCESS) {
                CERROR ("Can't query QP %s attributes: %d\n",
                        libcfs_nid2str(conn->ibc_peer->ibp_nid), frc);
                return -EIO;
        }
        
        return 0;
}

kib_conn_t *
kibnal_create_conn (lnet_nid_t nid, int proto_version)
{
        kib_conn_t  *conn;
        int          i;
        int          page_offset;
        int          ipage;
        int          rc;
        FSTATUS      frc;
        union {
                IB_QP_ATTRIBUTES_CREATE    qp_create;
                IB_QP_ATTRIBUTES_MODIFY    qp_attr;
        } params;
        
        LIBCFS_ALLOC (conn, sizeof (*conn));
        if (conn == NULL) {
                CERROR ("Can't allocate connection for %s\n",
                        libcfs_nid2str(nid));
                return (NULL);
        }

        /* zero flags, NULL pointers etc... */
        memset (conn, 0, sizeof (*conn));
        conn->ibc_state = IBNAL_CONN_INIT_NOTHING;
        conn->ibc_version = proto_version;

        INIT_LIST_HEAD (&conn->ibc_early_rxs);
        INIT_LIST_HEAD (&conn->ibc_tx_queue_nocred);
        INIT_LIST_HEAD (&conn->ibc_tx_queue);
        INIT_LIST_HEAD (&conn->ibc_tx_queue_rsrvd);
        INIT_LIST_HEAD (&conn->ibc_active_txs);
        spin_lock_init (&conn->ibc_lock);
        
        atomic_inc (&kibnal_data.kib_nconns);
        /* well not really, but I call destroy() on failure, which decrements */

        LIBCFS_ALLOC(conn->ibc_cvars, sizeof (*conn->ibc_cvars));
        if (conn->ibc_cvars == NULL) {
                CERROR ("Can't allocate connvars for %s\n", 
                        libcfs_nid2str(nid));
                goto failed;
        }
        memset(conn->ibc_cvars, 0, sizeof (*conn->ibc_cvars));

        LIBCFS_ALLOC(conn->ibc_rxs, IBNAL_RX_MSGS * sizeof (kib_rx_t));
        if (conn->ibc_rxs == NULL) {
                CERROR("Cannot allocate RX descriptors for %s\n",
                       libcfs_nid2str(nid));
                goto failed;
        }
        memset (conn->ibc_rxs, 0, IBNAL_RX_MSGS * sizeof(kib_rx_t));

        rc = kibnal_alloc_pages(&conn->ibc_rx_pages, IBNAL_RX_MSG_PAGES);
        if (rc != 0) {
                CERROR("Can't allocate RX buffers for %s\n",
                       libcfs_nid2str(nid));
                goto failed;
        }
        
        for (i = ipage = page_offset = 0; i < IBNAL_RX_MSGS; i++) {
                struct page *page = conn->ibc_rx_pages->ibp_pages[ipage];
                kib_rx_t    *rx = &conn->ibc_rxs[i];

                rx->rx_conn = conn;
                rx->rx_msg = (kib_msg_t *)(((char *)page_address(page)) + 
                             page_offset);

                rx->rx_hca_msg = kibnal_data.kib_whole_mem.md_addr +
                                 lnet_page2phys(page) + page_offset;
                
                page_offset += IBNAL_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= IBNAL_RX_MSG_PAGES);
                }
        }

        params.qp_create = (IB_QP_ATTRIBUTES_CREATE) {
                .Type                    = QPTypeReliableConnected,
                .SendQDepth              = (1 + IBNAL_MAX_RDMA_FRAGS) *
                                           (*kibnal_tunables.kib_concurrent_sends),
                .RecvQDepth              = IBNAL_RX_MSGS,
                .SendDSListDepth         = 1,
                .RecvDSListDepth         = 1,
                .SendCQHandle            = kibnal_data.kib_cq,
                .RecvCQHandle            = kibnal_data.kib_cq,
                .PDHandle                = kibnal_data.kib_pd,
                .SendSignaledCompletions = TRUE,
        };
        frc = iba_create_qp(kibnal_data.kib_hca, &params.qp_create, NULL,
                            &conn->ibc_qp, &conn->ibc_cvars->cv_qpattrs);
        if (frc != 0) {
                CERROR ("Can't create QP %s: %d\n", libcfs_nid2str(nid), frc);
                goto failed;
        }

        /* Mark QP created */
        kibnal_set_conn_state(conn, IBNAL_CONN_INIT_QP);

        params.qp_attr = (IB_QP_ATTRIBUTES_MODIFY) {
                .RequestState             = QPStateInit,
                .Attrs                    = (IB_QP_ATTR_PORTGUID |
                                             IB_QP_ATTR_PKEYINDEX |
                                             IB_QP_ATTR_ACCESSCONTROL),
                .PortGUID                 = kibnal_data.kib_port_guid,
                .PkeyIndex                = 0,
                .AccessControl = { 
                        .s = {
                                .RdmaWrite = 1,
                                .RdmaRead  = 1,
                        },
                },
        };
        frc = iba_modify_qp(conn->ibc_qp, &params.qp_attr, NULL);
        if (frc != 0) {
                CERROR ("Can't set QP %s state to INIT: %d\n",
                        libcfs_nid2str(nid), frc);
                goto failed;
        }

        frc = iba_query_qp(conn->ibc_qp, &conn->ibc_cvars->cv_qpattrs, NULL);
        if (frc != FSUCCESS) {
                CERROR ("Can't query QP %s attributes: %d\n",
                        libcfs_nid2str(nid), frc);
                goto failed;
        }

        /* 1 ref for caller */
        atomic_set (&conn->ibc_refcount, 1);
        CDEBUG(D_NET, "New conn %p\n", conn);
        return (conn);
        
 failed:
        kibnal_destroy_conn (conn);
        return (NULL);
}

void
kibnal_destroy_conn (kib_conn_t *conn)
{
        FSTATUS frc;

        LASSERT (!in_interrupt());
        
        CDEBUG (D_NET, "connection %s\n", 
                (conn->ibc_peer) == NULL ? "<ANON>" :
                libcfs_nid2str(conn->ibc_peer->ibp_nid));

        LASSERT (atomic_read (&conn->ibc_refcount) == 0);
        LASSERT (list_empty(&conn->ibc_early_rxs));
        LASSERT (list_empty(&conn->ibc_tx_queue));
        LASSERT (list_empty(&conn->ibc_tx_queue_rsrvd));
        LASSERT (list_empty(&conn->ibc_tx_queue_nocred));
        LASSERT (list_empty(&conn->ibc_active_txs));
        LASSERT (conn->ibc_nsends_posted == 0);

        switch (conn->ibc_state) {
        case IBNAL_CONN_INIT_NOTHING:
        case IBNAL_CONN_INIT_QP:
        case IBNAL_CONN_DISCONNECTED:
                break;

        default:
                /* conn must either have never engaged with the CM, or have
                 * completely disengaged from it */
                CERROR("Bad conn %s state %d\n",
                       (conn->ibc_peer) == NULL ? "<anon>" :
                       libcfs_nid2str(conn->ibc_peer->ibp_nid), conn->ibc_state);
                LBUG();
        }

        if (conn->ibc_cep != NULL) {
                frc = iba_cm_destroy_cep(conn->ibc_cep);
                if (frc != FSUCCESS)
                        CERROR("Error destroying CEP %p: %d\n",
                               conn->ibc_cep, frc);
        }

        if (conn->ibc_qp != NULL) {
                frc = iba_destroy_qp(conn->ibc_qp);
                if (frc != FSUCCESS)
                        CERROR("Error destroying QP %p: %d\n",
                               conn->ibc_qp, frc);
        }

        if (conn->ibc_rx_pages != NULL) 
                kibnal_free_pages(conn->ibc_rx_pages);
        
        if (conn->ibc_rxs != NULL)
                LIBCFS_FREE(conn->ibc_rxs, 
                            IBNAL_RX_MSGS * sizeof(kib_rx_t));

        if (conn->ibc_cvars != NULL)
                LIBCFS_FREE(conn->ibc_cvars, sizeof(*conn->ibc_cvars));

        if (conn->ibc_peer != NULL)
                kibnal_peer_decref(conn->ibc_peer);

        LIBCFS_FREE(conn, sizeof (*conn));

        atomic_dec(&kibnal_data.kib_nconns);
}

int
kibnal_close_peer_conns_locked (kib_peer_t *peer, int why)
{
        kib_conn_t         *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry (ctmp, kib_conn_t, ibc_list);

                count++;
                kibnal_close_conn_locked (conn, why);
        }

        return (count);
}

int
kibnal_close_stale_conns_locked (kib_peer_t *peer, __u64 incarnation)
{
        kib_conn_t         *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry (ctmp, kib_conn_t, ibc_list);

                if (conn->ibc_incarnation == incarnation)
                        continue;

                CDEBUG(D_NET, "Closing stale conn nid:%s incarnation:"LPX64"("LPX64")\n",
                       libcfs_nid2str(peer->ibp_nid), 
                       conn->ibc_incarnation, incarnation);
                
                count++;
                kibnal_close_conn_locked (conn, -ESTALE);
        }

        return (count);
}

int
kibnal_close_matching_conns (lnet_nid_t nid)
{
        unsigned long       flags;
        kib_peer_t         *peer;
        struct list_head   *ptmp;
        struct list_head   *pnxt;
        int                 lo;
        int                 hi;
        int                 i;
        int                 count = 0;

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        if (nid != LNET_NID_ANY)
                lo = hi = kibnal_nid2peerlist(nid) - kibnal_data.kib_peers;
        else {
                lo = 0;
                hi = kibnal_data.kib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kibnal_data.kib_peers[i]) {

                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 kibnal_peer_connecting(peer) ||
                                 !list_empty (&peer->ibp_conns));

                        if (!(nid == LNET_NID_ANY || nid == peer->ibp_nid))
                                continue;

                        count += kibnal_close_peer_conns_locked (peer, 0);
                }
        }

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        /* wildcards always succeed */
        if (nid == LNET_NID_ANY)
                return (0);
        
        return (count == 0 ? -ENOENT : 0);
}

int
kibnal_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg)
{
        struct libcfs_ioctl_data *data = arg;
        int                       rc = -EINVAL;
        ENTRY;

        LASSERT (ni == kibnal_data.kib_ni);

        switch(cmd) {
        case IOC_LIBCFS_GET_PEER: {
                lnet_nid_t   nid = 0;
                int          share_count = 0;

                rc = kibnal_get_peer_info(data->ioc_count,
                                          &nid, &share_count);
                data->ioc_nid   = nid;
                data->ioc_count = share_count;
                break;
        }
        case IOC_LIBCFS_ADD_PEER: {
                rc = kibnal_add_persistent_peer (data->ioc_nid);
                break;
        }
        case IOC_LIBCFS_DEL_PEER: {
                rc = kibnal_del_peer (data->ioc_nid);
                break;
        }
        case IOC_LIBCFS_GET_CONN: {
                kib_conn_t *conn = kibnal_get_conn_by_idx (data->ioc_count);

                if (conn == NULL)
                        rc = -ENOENT;
                else {
                        rc = 0;
                        data->ioc_nid = conn->ibc_peer->ibp_nid;
                        kibnal_conn_decref(conn);
                }
                break;
        }
        case IOC_LIBCFS_CLOSE_CONNECTION: {
                rc = kibnal_close_matching_conns (data->ioc_nid);
                break;
        }
        case IOC_LIBCFS_REGISTER_MYNID: {
                if (ni->ni_nid == data->ioc_nid) {
                        rc = 0;
                } else {
                        CERROR("obsolete IOC_LIBCFS_REGISTER_MYNID: %s(%s)\n",
                               libcfs_nid2str(data->ioc_nid),
                               libcfs_nid2str(ni->ni_nid));
                        rc = -EINVAL;
                }
                break;
        }
        }

        RETURN(rc);
}

void
kibnal_free_pages (kib_pages_t *p)
{
        int     npages = p->ibp_npages;
        int     i;
        
        for (i = 0; i < npages; i++)
                if (p->ibp_pages[i] != NULL)
                        __free_page(p->ibp_pages[i]);
        
        LIBCFS_FREE (p, offsetof(kib_pages_t, ibp_pages[npages]));
}

int
kibnal_alloc_pages (kib_pages_t **pp, int npages)
{
        kib_pages_t   *p;
        int            i;

        LIBCFS_ALLOC(p, offsetof(kib_pages_t, ibp_pages[npages]));
        if (p == NULL) {
                CERROR ("Can't allocate buffer %d\n", npages);
                return (-ENOMEM);
        }

        memset (p, 0, offsetof(kib_pages_t, ibp_pages[npages]));
        p->ibp_npages = npages;
        
        for (i = 0; i < npages; i++) {
                p->ibp_pages[i] = alloc_page (GFP_KERNEL);
                if (p->ibp_pages[i] == NULL) {
                        CERROR ("Can't allocate page %d of %d\n", i, npages);
                        kibnal_free_pages(p);
                        return (-ENOMEM);
                }
        }

        *pp = p;
        return (0);
}

int
kibnal_alloc_tx_descs (void) 
{
        int    i;
        
        LIBCFS_ALLOC (kibnal_data.kib_tx_descs,
                      IBNAL_TX_MSGS() * sizeof(kib_tx_t));
        if (kibnal_data.kib_tx_descs == NULL)
                return -ENOMEM;
        
        memset(kibnal_data.kib_tx_descs, 0,
               IBNAL_TX_MSGS() * sizeof(kib_tx_t));

        for (i = 0; i < IBNAL_TX_MSGS(); i++) {
                kib_tx_t *tx = &kibnal_data.kib_tx_descs[i];

#if IBNAL_USE_FMR
                LIBCFS_ALLOC(tx->tx_pages, LNET_MAX_IOV *
                             sizeof(*tx->tx_pages));
                if (tx->tx_pages == NULL)
                        return -ENOMEM;
#else
                LIBCFS_ALLOC(tx->tx_wrq, 
                             (1 + IBNAL_MAX_RDMA_FRAGS) * 
                             sizeof(*tx->tx_wrq));
                if (tx->tx_wrq == NULL)
                        return -ENOMEM;
                
                LIBCFS_ALLOC(tx->tx_gl, 
                             (1 + IBNAL_MAX_RDMA_FRAGS) * 
                             sizeof(*tx->tx_gl));
                if (tx->tx_gl == NULL)
                        return -ENOMEM;
                
                LIBCFS_ALLOC(tx->tx_rd, 
                             offsetof(kib_rdma_desc_t, 
                                      rd_frags[IBNAL_MAX_RDMA_FRAGS]));
                if (tx->tx_rd == NULL)
                        return -ENOMEM;
#endif
        }

        return 0;
}

void
kibnal_free_tx_descs (void) 
{
        int    i;

        if (kibnal_data.kib_tx_descs == NULL)
                return;

        for (i = 0; i < IBNAL_TX_MSGS(); i++) {
                kib_tx_t *tx = &kibnal_data.kib_tx_descs[i];

#if IBNAL_USE_FMR
                if (tx->tx_pages != NULL)
                        LIBCFS_FREE(tx->tx_pages, LNET_MAX_IOV *
                                    sizeof(*tx->tx_pages));
#else
                if (tx->tx_wrq != NULL)
                        LIBCFS_FREE(tx->tx_wrq, 
                                    (1 + IBNAL_MAX_RDMA_FRAGS) * 
                                    sizeof(*tx->tx_wrq));

                if (tx->tx_gl != NULL)
                        LIBCFS_FREE(tx->tx_gl, 
                                    (1 + IBNAL_MAX_RDMA_FRAGS) * 
                                    sizeof(*tx->tx_gl));

                if (tx->tx_rd != NULL)
                        LIBCFS_FREE(tx->tx_rd, 
                                    offsetof(kib_rdma_desc_t, 
                                             rd_frags[IBNAL_MAX_RDMA_FRAGS]));
#endif
        }

        LIBCFS_FREE(kibnal_data.kib_tx_descs,
                    IBNAL_TX_MSGS() * sizeof(kib_tx_t));
}

int
kibnal_setup_tx_descs (void)
{
        int           ipage = 0;
        int           page_offset = 0;
        struct page  *page;
        kib_tx_t     *tx;
        int           i;
        int           rc;

        /* pre-mapped messages are not bigger than 1 page */
        CLASSERT (IBNAL_MSG_SIZE <= PAGE_SIZE);

        /* No fancy arithmetic when we do the buffer calculations */
        CLASSERT (PAGE_SIZE % IBNAL_MSG_SIZE == 0);

        rc = kibnal_alloc_pages(&kibnal_data.kib_tx_pages,
                                IBNAL_TX_MSG_PAGES());
        if (rc != 0)
                return (rc);

        for (i = 0; i < IBNAL_TX_MSGS(); i++) {
                page = kibnal_data.kib_tx_pages->ibp_pages[ipage];
                tx = &kibnal_data.kib_tx_descs[i];

#if IBNAL_USE_FMR
                /* Allocate an FMR for this TX so it can map src/sink buffers
                 * for large transfers */
#endif
                tx->tx_msg = (kib_msg_t *)(((char *)page_address(page)) + 
                                            page_offset);

                tx->tx_hca_msg = kibnal_data.kib_whole_mem.md_addr +
                                 lnet_page2phys(page) + page_offset;

                CDEBUG(D_NET, "Tx[%d] %p->%p - "LPX64"\n", 
                       i, tx, tx->tx_msg, tx->tx_hca_msg);

                list_add (&tx->tx_list, &kibnal_data.kib_idle_txs);

                page_offset += IBNAL_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= IBNAL_TX_MSG_PAGES());
                }
        }
        
        return (0);
}

int
kibnal_register_all_memory(void)
{
        /* CAVEAT EMPTOR: this assumes all physical memory is in 1 contiguous
         * chunk starting at 0 */
        struct sysinfo     si;
        __u64              total;
        __u64              total2;
        __u64              roundup = (128<<20);     /* round up in big chunks */
        IB_MR_PHYS_BUFFER  phys;
        IB_ACCESS_CONTROL  access;
        FSTATUS            frc;

        memset(&access, 0, sizeof(access));
        access.s.MWBindable = 1;
        access.s.LocalWrite = 1;
        access.s.RdmaRead = 1;
        access.s.RdmaWrite = 1;

        /* XXX we don't bother with first-gen cards */
        if (kibnal_data.kib_hca_attrs.VendorId == 0xd0b7 && 
            kibnal_data.kib_hca_attrs.DeviceId == 0x3101) {
                CERROR("Can't register all memory on first generation HCAs\n");
                return -EINVAL;
        }

        si_meminfo(&si);

        CDEBUG(D_NET, "si_meminfo: %lu/%u, num_physpages %lu/%lu\n",
               si.totalram, si.mem_unit, num_physpages, PAGE_SIZE);

        total = ((__u64)si.totalram) * si.mem_unit;
        total2 = num_physpages * PAGE_SIZE;
        if (total < total2)
                total = total2;

        if (total == 0) {
                CERROR("Can't determine memory size\n");
                return -ENOMEM;
        }
                 
        roundup = (128<<20);
        total = (total + (roundup - 1)) & ~(roundup - 1);

        phys.PhysAddr = 0;
        phys.Length = total;

        frc = iba_register_contig_pmr(kibnal_data.kib_hca, 0, &phys, 1, 0,
                                      kibnal_data.kib_pd, access,
                                      &kibnal_data.kib_whole_mem.md_handle,
                                      &kibnal_data.kib_whole_mem.md_addr,
                                      &kibnal_data.kib_whole_mem.md_lkey,
                                      &kibnal_data.kib_whole_mem.md_rkey);

        if (frc != FSUCCESS) {
                CERROR("registering physical memory failed: %d\n", frc);
                return -EIO;
        }

        CDEBUG(D_WARNING, "registered phys mem from 0("LPX64") for "LPU64"("LPU64") -> "LPX64"\n",
               phys.PhysAddr, total, phys.Length, kibnal_data.kib_whole_mem.md_addr);

        return 0;
}

void
kibnal_shutdown (lnet_ni_t *ni)
{
        int   i;
        int   rc;

        LASSERT (ni == kibnal_data.kib_ni);
        LASSERT (ni->ni_data == &kibnal_data);
       
        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
               atomic_read (&libcfs_kmemory));

        switch (kibnal_data.kib_init) {
        default:
                CERROR ("Unexpected state %d\n", kibnal_data.kib_init);
                LBUG();

        case IBNAL_INIT_ALL:
                /* stop accepting connections, prevent new peers and start to
                 * tear down all existing ones... */
                kibnal_stop_listener(1);

                /* Wait for all peer state to clean up */
                i = 2;
                while (atomic_read (&kibnal_data.kib_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "waiting for %d peers to disconnect\n",
                               atomic_read (&kibnal_data.kib_npeers));
                        set_current_state (TASK_UNINTERRUPTIBLE);
                        schedule_timeout (HZ);
                }
                /* fall through */

        case IBNAL_INIT_CQ:
                rc = iba_destroy_cq(kibnal_data.kib_cq);
                if (rc != 0)
                        CERROR ("Destroy CQ error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_TXD:
                kibnal_free_pages (kibnal_data.kib_tx_pages);
                /* fall through */

        case IBNAL_INIT_MD:
                rc = iba_deregister_mr(kibnal_data.kib_whole_mem.md_handle);
                if (rc != FSUCCESS)
                        CERROR ("Deregister memory: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_PD:
                rc = iba_free_pd(kibnal_data.kib_pd);
                if (rc != 0)
                        CERROR ("Destroy PD error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_SD:
                rc = iba_sd_deregister(kibnal_data.kib_sd);
                if (rc != 0)
                        CERROR ("Deregister SD error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_PORTATTRS:
                LIBCFS_FREE(kibnal_data.kib_hca_attrs.PortAttributesList,
                            kibnal_data.kib_hca_attrs.PortAttributesListSize);
                /* fall through */

        case IBNAL_INIT_HCA:
                rc = iba_close_ca(kibnal_data.kib_hca);
                if (rc != 0)
                        CERROR ("Close HCA  error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_DATA:
                LASSERT (atomic_read (&kibnal_data.kib_npeers) == 0);
                LASSERT (kibnal_data.kib_peers != NULL);
                for (i = 0; i < kibnal_data.kib_peer_hash_size; i++) {
                        LASSERT (list_empty (&kibnal_data.kib_peers[i]));
                }
                LASSERT (atomic_read (&kibnal_data.kib_nconns) == 0);
                LASSERT (list_empty (&kibnal_data.kib_connd_zombies));
                LASSERT (list_empty (&kibnal_data.kib_connd_conns));
                LASSERT (list_empty (&kibnal_data.kib_connd_peers));

                /* flag threads to terminate; wake and wait for them to die */
                kibnal_data.kib_shutdown = 1;
                wake_up_all (&kibnal_data.kib_sched_waitq);
                wake_up_all (&kibnal_data.kib_connd_waitq);

                i = 2;
                while (atomic_read (&kibnal_data.kib_nthreads) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "Waiting for %d threads to terminate\n",
                               atomic_read (&kibnal_data.kib_nthreads));
                        set_current_state (TASK_INTERRUPTIBLE);
                        schedule_timeout (HZ);
                }
                /* fall through */
                
        case IBNAL_INIT_NOTHING:
                break;
        }

        kibnal_free_tx_descs();

        if (kibnal_data.kib_peers != NULL)
                LIBCFS_FREE (kibnal_data.kib_peers,
                             sizeof (struct list_head) * 
                             kibnal_data.kib_peer_hash_size);

        CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
               atomic_read (&libcfs_kmemory));

        kibnal_data.kib_init = IBNAL_INIT_NOTHING;
        PORTAL_MODULE_UNUSE;
}

int 
kibnal_get_ipif_name(char *ifname, int ifname_size, int idx)
{
        char  *basename = *kibnal_tunables.kib_ipif_basename;
        int    n = strlen(basename);
        int    baseidx;
        int    m;

        if (n == 0) {                           /* empty string */
                CERROR("Empty IP interface basename specified\n");
                return -EINVAL;
        }

        for (m = n; m > 0; m--)                 /* find max numeric postfix */
                if (sscanf(basename + m - 1, "%d", &baseidx) != 1)
                        break;

        if (m == 0)                             /* just a number */
                m = n;

        if (m == n)                             /* no postfix */
                baseidx = 1;                    /* default to 1 */

        if (m >= ifname_size)
                m = ifname_size - 1;

        memcpy(ifname, basename, m);            /* copy prefix name */
        
        snprintf(ifname + m, ifname_size - m, "%d", baseidx + idx);
        
        if (strlen(ifname) == ifname_size - 1) {
                CERROR("IP interface basename %s too long\n", basename);
                return -EINVAL;
        }
        
        return 0;
}

int
kibnal_startup (lnet_ni_t *ni)
{
        char                ipif_name[32];
        __u32               ip;
        __u32               netmask;
        int                 up;
        int                 nob;
        struct timeval      tv;
        IB_PORT_ATTRIBUTES *pattr;
        FSTATUS             frc;
        int                 rc;
        __u32               n;
        int                 i;

        LASSERT (ni->ni_lnd == &the_kiblnd);

        /* Only 1 instance supported */
        if (kibnal_data.kib_init != IBNAL_INIT_NOTHING) {
                CERROR ("Only 1 instance supported\n");
                return -EPERM;
        }

        if (*kibnal_tunables.kib_credits > *kibnal_tunables.kib_ntx) {
                CERROR ("Can't set credits(%d) > ntx(%d)\n",
                        *kibnal_tunables.kib_credits,
                        *kibnal_tunables.kib_ntx);
                return -EINVAL;
        }

        ni->ni_maxtxcredits = *kibnal_tunables.kib_credits;
        ni->ni_peertxcredits = *kibnal_tunables.kib_peercredits;

        CLASSERT (LNET_MAX_INTERFACES > 1);

        if (ni->ni_interfaces[0] == NULL) {
                kibnal_data.kib_hca_idx = 0;
        } else {
                /* Use the HCA specified in 'networks=' */
                if (ni->ni_interfaces[1] != NULL) {
                        CERROR("Multiple interfaces not supported\n");
                        return -EPERM;
                }
                
                /* Parse <number> into kib_hca_idx */
                nob = strlen(ni->ni_interfaces[0]);
                if (sscanf(ni->ni_interfaces[0], "%d%n", 
                           &kibnal_data.kib_hca_idx, &nob) < 1 ||
                    nob != strlen(ni->ni_interfaces[0])) {
                        CERROR("Can't parse interface '%s'\n",
                               ni->ni_interfaces[0]);
                        return -EINVAL;
                }
        }

        rc = kibnal_get_ipif_name(ipif_name, sizeof(ipif_name),
                                  kibnal_data.kib_hca_idx);
        if (rc != 0)
                return rc;
        
        rc = libcfs_ipif_query(ipif_name, &up, &ip, &netmask);
        if (rc != 0) {
                CERROR("Can't query IPoIB interface %s: %d\n", ipif_name, rc);
                return -ENETDOWN;
        }
        
        if (!up) {
                CERROR("Can't query IPoIB interface %s: it's down\n", ipif_name);
                return -ENETDOWN;
        }
        
        ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), ip);

        ni->ni_data = &kibnal_data;
        kibnal_data.kib_ni = ni;

        do_gettimeofday(&tv);
        kibnal_data.kib_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;

        PORTAL_MODULE_USE;

        rwlock_init(&kibnal_data.kib_global_lock);

        kibnal_data.kib_peer_hash_size = IBNAL_PEER_HASH_SIZE;
        LIBCFS_ALLOC (kibnal_data.kib_peers,
                      sizeof (struct list_head) * kibnal_data.kib_peer_hash_size);
        if (kibnal_data.kib_peers == NULL) {
                goto failed;
        }
        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++)
                INIT_LIST_HEAD(&kibnal_data.kib_peers[i]);

        spin_lock_init (&kibnal_data.kib_connd_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_connd_peers);
        INIT_LIST_HEAD (&kibnal_data.kib_connd_conns);
        INIT_LIST_HEAD (&kibnal_data.kib_connd_zombies);
        init_waitqueue_head (&kibnal_data.kib_connd_waitq);

        spin_lock_init (&kibnal_data.kib_sched_lock);
        init_waitqueue_head (&kibnal_data.kib_sched_waitq);

        spin_lock_init (&kibnal_data.kib_tx_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_idle_txs);

        rc = kibnal_alloc_tx_descs();
        if (rc != 0) {
                CERROR("Can't allocate tx descs\n");
                goto failed;
        }

        /* lists/ptrs/locks initialised */
        kibnal_data.kib_init = IBNAL_INIT_DATA;
        /*****************************************************/

        kibnal_data.kib_sdretry.RetryCount = *kibnal_tunables.kib_sd_retries;
        kibnal_data.kib_sdretry.Timeout = (*kibnal_tunables.kib_timeout * 1000)/
                                          *kibnal_tunables.kib_sd_retries;

        for (i = 0; i < IBNAL_N_SCHED; i++) {
                rc = kibnal_thread_start (kibnal_scheduler,
                                          (void *)(unsigned long)i);
                if (rc != 0) {
                        CERROR("Can't spawn iib scheduler[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        rc = kibnal_thread_start (kibnal_connd, NULL);
        if (rc != 0) {
                CERROR ("Can't spawn iib connd: %d\n", rc);
                goto failed;
        }

        n = sizeof(kibnal_data.kib_hca_guids) /
            sizeof(kibnal_data.kib_hca_guids[0]);
        frc = iba_get_caguids(&n, kibnal_data.kib_hca_guids);
        if (frc != FSUCCESS) {
                CERROR ("Can't get HCA guids: %d\n", frc);
                goto failed;
        }

        if (n == 0) {
                CERROR ("No HCAs found\n");
                goto failed;
        }

        if (n <= kibnal_data.kib_hca_idx) {
                CERROR("Invalid HCA %d requested: (must be 0 - %d inclusive)\n",
                       kibnal_data.kib_hca_idx, n - 1);
                goto failed;
        }
        
        /* Infinicon has per-HCA notification callbacks */
        frc = iba_open_ca(kibnal_data.kib_hca_guids[kibnal_data.kib_hca_idx],
                            kibnal_hca_callback,
                            kibnal_hca_async_callback,
                            NULL,
                            &kibnal_data.kib_hca);
        if (frc != FSUCCESS) {
                CERROR ("Can't open HCA[%d]: %d\n", 
                        kibnal_data.kib_hca_idx, frc);
                goto failed;
        }
        
        /* Channel Adapter opened */
        kibnal_data.kib_init = IBNAL_INIT_HCA;
        /*****************************************************/

        kibnal_data.kib_hca_attrs.PortAttributesList = NULL;
        kibnal_data.kib_hca_attrs.PortAttributesListSize = 0;
        frc = iba_query_ca(kibnal_data.kib_hca,
                           &kibnal_data.kib_hca_attrs, NULL);
        if (frc != FSUCCESS) {
                CERROR ("Can't size port attrs: %d\n", frc);
                goto failed;
        }
        
        LIBCFS_ALLOC(kibnal_data.kib_hca_attrs.PortAttributesList,
                     kibnal_data.kib_hca_attrs.PortAttributesListSize);
        if (kibnal_data.kib_hca_attrs.PortAttributesList == NULL)
                goto failed;

        /* Port attrs allocated */
        kibnal_data.kib_init = IBNAL_INIT_PORTATTRS;
        /*****************************************************/
        
        frc = iba_query_ca(kibnal_data.kib_hca, &kibnal_data.kib_hca_attrs,
                           NULL);
        if (frc != FSUCCESS) {
                CERROR ("Can't get port attrs for HCA %d: %d\n",
                        kibnal_data.kib_hca_idx, frc);
                goto failed;
        }

        for (i = 0, pattr = kibnal_data.kib_hca_attrs.PortAttributesList;
             pattr != NULL;
             i++, pattr = pattr->Next) {
                switch (pattr->PortState) {
                default:
                        CERROR("Unexpected port[%d] state %d\n",
                               i, pattr->PortState);
                        continue;
                case PortStateDown:
                        CDEBUG(D_NET, "port[%d] Down\n", i);
                        continue;
                case PortStateInit:
                        CDEBUG(D_NET, "port[%d] Init\n", i);
                        continue;
                case PortStateArmed:
                        CDEBUG(D_NET, "port[%d] Armed\n", i);
                        continue;
                        
                case PortStateActive:
                        CDEBUG(D_NET, "port[%d] Active\n", i);
                        kibnal_data.kib_port = i;
                        kibnal_data.kib_port_guid = pattr->GUID;
                        kibnal_data.kib_port_pkey = pattr->PkeyTable[0];
                        break;
                }
                break;
        }

        if (pattr == NULL) {
                CERROR ("Can't find an active port\n");
                goto failed;
        }

        CDEBUG(D_NET, "got guid "LPX64"\n", kibnal_data.kib_port_guid);
        
        frc = iba_sd_register(&kibnal_data.kib_sd, NULL);
        if (frc != FSUCCESS) {
                CERROR ("Can't register with SD: %d\n", frc);
                goto failed;
        }
        
        /* Registered with SD OK */
        kibnal_data.kib_init = IBNAL_INIT_SD;
        /*****************************************************/

        frc = iba_alloc_pd(kibnal_data.kib_hca, 0, &kibnal_data.kib_pd);
        if (frc != FSUCCESS) {
                CERROR ("Can't create PD: %d\n", rc);
                goto failed;
        }
        
        /* flag PD initialised */
        kibnal_data.kib_init = IBNAL_INIT_PD;
        /*****************************************************/

        rc = kibnal_register_all_memory();
        if (rc != 0) {
                CERROR ("Can't register all memory\n");
                goto failed;
        }
        
        /* flag whole memory MD initialised */
        kibnal_data.kib_init = IBNAL_INIT_MD;
        /*****************************************************/

        rc = kibnal_setup_tx_descs();
        if (rc != 0) {
                CERROR ("Can't register tx descs: %d\n", rc);
                goto failed;
        }
        
        /* flag TX descs initialised */
        kibnal_data.kib_init = IBNAL_INIT_TXD;
        /*****************************************************/
        
        frc = iba_create_cq(kibnal_data.kib_hca, IBNAL_CQ_ENTRIES(),
                            &kibnal_data.kib_cq, &kibnal_data.kib_cq,
                            &n);
        if (frc != FSUCCESS) {
                CERROR ("Can't create RX CQ: %d\n", frc);
                goto failed;
        }

        /* flag CQ initialised */
        kibnal_data.kib_init = IBNAL_INIT_CQ;
        /*****************************************************/
        
        if (n < IBNAL_CQ_ENTRIES()) {
                CERROR ("CQ only has %d entries: %d needed\n", 
                        n, IBNAL_CQ_ENTRIES());
                goto failed;
        }

        rc = iba_rearm_cq(kibnal_data.kib_cq, CQEventSelNextWC);
        if (rc != 0) {
                CERROR ("Failed to re-arm completion queue: %d\n", rc);
                goto failed;
        }
        
        rc = kibnal_start_listener();
        if (rc != 0) {
                CERROR("Can't start listener: %d\n", rc);
                goto failed;
        }

        /* flag everything initialised */
        kibnal_data.kib_init = IBNAL_INIT_ALL;
        /*****************************************************/

        return (0);

 failed:
        kibnal_shutdown (ni);    
        return (-ENETDOWN);
}

void __exit
kibnal_module_fini (void)
{
        lnet_unregister_lnd(&the_kiblnd);
        kibnal_tunables_fini();
}

int __init
kibnal_module_init (void)
{
        int    rc;

        rc = kibnal_tunables_init();
        if (rc != 0)
                return rc;

        lnet_register_lnd(&the_kiblnd);

        return 0;
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Kernel Infinicon IB LND v1.00");
MODULE_LICENSE("GPL");

module_init(kibnal_module_init);
module_exit(kibnal_module_fini);
