#!/usr/bin/env python

"""
Copyright 2019 Cray Inc.  All Rights Reserved
Utility to maps numeric opcode to string identifier
"""

from pykdump.API import *
import argparse

description_short = "Maps Lustre rpc opcodes string identifiers."

opcodes = {
    0:  'OST_REPLY',
    1:  'OST_GETATTR',
    2:  'OST_SETATTR',
    3:  'OST_READ',
    4:  'OST_WRITE',
    5:  'OST_CREATE',
    6:  'OST_DESTROY',
    7:  'OST_GET_INFO',
    8:  'OST_CONNECT',
    9:  'OST_DISCONNECT',
    10: 'OST_PUNCH',
    11: 'OST_OPEN',
    12: 'OST_CLOSE',
    13: 'OST_STATFS',
    16: 'OST_SYNC',
    17: 'OST_SET_INFO',
    18: 'OST_QUOTACHECK',
    19: 'OST_QUOTACTL',
    20: 'OST_QUOTA_ADJUST_QUNIT',  # not used since 2.4
    21: 'OST_LADVISE',

    33: 'MDS_GETATTR',
    34: 'MDS_GETATTR_NAME',
    35: 'MDS_CLOSE',
    36: 'MDS_REINT',
    37: 'MDS_READPAGE',
    38: 'MDS_CONNECT',
    39: 'MDS_DISCONNECT',
    40: 'MDS_GET_ROOT',
    41: 'MDS_STATFS',
    42: 'MDS_PIN',
    43: 'MDS_UNPIN',          # obsolete, never used in a release
    44: 'MDS_SYNC',
    45: 'MDS_DONE_WRITING',
    46: 'MDS_SET_INFO',
    47: 'MDS_QUOTACHECK',     # not used since 2.4
    48: 'MDS_QUOTACTL',
    49: 'MDS_GETXATTR',
    50: 'MDS_SETXATTR',       # obsolete, now it's MDS_REINT op
    51: 'MDS_WRITEPAGE',
    52: 'MDS_IS_SUBDIR',      # obsolete, never used in a release
    53: 'MDS_GET_INFO',
    54: 'MDS_HSM_STATE_GET',
    55: 'MDS_HSM_STATE_SET',
    56: 'MDS_HSM_ACTION',
    57: 'MDS_HSM_PROGRESS',
    58: 'MDS_HSM_REQUEST',
    59: 'MDS_HSM_CT_REGISTER',
    60: 'MDS_HSM_CT_UNREGISTER',
    61: 'MDS_SWAP_LAYOUTS',

    101: 'LDLM_ENQUEUE',
    102: 'LDLM_CONVERT',
    103: 'LDLM_CANCEL',
    104: 'LDLM_BL_CALLBACK',
    105: 'LDLM_CP_CALLBACK',
    106: 'LDLM_GL_CALLBACK',
    107: 'LDLM_SET_INFO',

    250: 'MGS_CONNECT',
    251: 'MGS_DISCONNECT',
    252: 'MGS_EXCEPTION',           # node died, etc.
    253: 'MGS_TARGET_REG',          # whenever target starts up
    254: 'MGS_TARGET_DEL',
    255: 'MGS_SET_INFO',
    256: 'MGS_CONFIG_READ',

    400: 'OBD_PING',
    401: 'OBD_LOG_CANCEL',          # obsolete since 1.5
    402: 'OBD_QC_CALLBACK',         # obsolete since 2.4
    403: 'OBD_IDX_READ',

    501: 'LLOG_ORIGIN_HANDLE_CREATE',
    502: 'LLOG_ORIGIN_HANDLE_NEXT_BLOCK',
    503: 'LLOG_ORIGIN_HANDLE_READ_HEADER',
    504: 'LLOG_ORIGIN_HANDLE_WRITE_REC',    # Obsolete by 2.1.
    505: 'LLOG_ORIGIN_HANDLE_CLOSE',        # Obsolete by 1.8.
    506: 'LLOG_ORIGIN_CONNECT',             # Obsolete by 2.4.
    507: 'LLOG_CATINFO',                    # Obsolete by 2.3.
    508: 'LLOG_ORIGIN_HANDLE_PREV_BLOCK',
    509: 'LLOG_ORIGIN_HANDLE_DESTROY',      # Obsolete by 2.11.

    601: 'QUOTA_DQACQ',
    602: 'QUOTA_DQREL',

    700: 'SEQ_QUERY',

    801: 'SEC_CTX_INIT',
    802: 'SEC_CTX_INIT_CONT',
    803: 'SEC_CTX_FINI',

    900: 'FLD_QUERY',
    901: 'FLD_READ',

    1000: 'OUT_UPDATE',

    1101: 'LFSCK_NOTIFY',
    1102: 'LFSCK_QUERY'
}

def translate_opcodes(opc_list):
    for opc in opc_list:
        try:
            print "o%d \t= %s" % (opc, opcodes[opc])
        except:
            print "o%d \t= unknown" % opc


if __name__ == "__main__":
    description = "Maps one or more Lustre rpc opcodes to its string identifier."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('opcode', nargs="+", type=int,
        help="list of one or more opcodes")

    args = parser.parse_args()
    translate_opcodes(args.opcode)
