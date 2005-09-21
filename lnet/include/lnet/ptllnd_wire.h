/************************************************************************
 * Tunable defaults that {u,k}lnds/ptllnd should have in common.
 */

#define PTLLND_PORTAL           9          /* The same portal PTLPRC used when talking to cray portals */
#define PTLLND_PEERCREDITS      8          /* concurrent sends to 1 peer*/
#define PTLLND_MAX_MSG_SIZE     512        /* Maximum message size */


/************************************************************************
 * Portal NAL Wire message format.
 * These are sent in sender's byte order (i.e. receiver flips).
 */

#define PTL_RESERVED_MATCHBITS  0x100   /* below this value is reserved
                                         * above is for bult data transfer */
#define LNET_MSG_MATCHBITS       0       /* the value for the message channel */

typedef struct
{
        lnet_hdr_t        kptlim_hdr;             /* portals header */
        char              kptlim_payload[0];      /* piggy-backed payload */
} WIRE_ATTR kptl_immediate_msg_t;

typedef struct
{
        lnet_hdr_t        kptlrm_hdr;             /* portals header */
        __u64             kptlrm_matchbits;       /* matchbits */
} WIRE_ATTR kptl_request_msg_t;

typedef struct
{
        __u64             kptlhm_matchbits;       /* matchbits */
        __u32             kptlhm_max_immd_size;   /* immd message size */
} WIRE_ATTR kptl_hello_msg_t;

typedef struct kptl_msg
{
        /* First 2 fields fixed FOR ALL TIME */
        __u32           ptlm_magic;     /* I'm an ptl NAL message */
        __u16           ptlm_version;   /* this is my version number */
        __u8            ptlm_type;      /* the message type */
        __u8            ptlm_credits;   /* returned credits */
        __u32           ptlm_nob;       /* # bytes in whole message */
        __u32           ptlm_cksum;     /* checksum (0 == no checksum) */
        __u64           ptlm_srcnid;    /* sender's NID */
        __u64           ptlm_srcstamp;  /* sender's incarnation */
        __u64           ptlm_dstnid;    /* destination's NID */
        __u64           ptlm_dststamp;  /* destination's incarnation */
        __u64           ptlm_seq;       /* sequence number */

         union {
                kptl_immediate_msg_t    immediate;
                kptl_request_msg_t      req;
                kptl_hello_msg_t        hello;
        } WIRE_ATTR ptlm_u;

}kptl_msg_t;

#define PTLLND_MSG_MAGIC                0x50746C4E  /* 'PtlN' unique magic */
#define PTLLND_MSG_VERSION              0x01

#define PTLLND_MSG_TYPE_INVALID         0x00
#define PLTLND_MSG_TYPE_PUT             0x01
#define PTLLND_MSG_TYPE_GET             0x02
#define PTLLND_MSG_TYPE_IMMEDIATE       0x03    /* No bulk data xfer*/
#define PTLLND_MSG_TYPE_NOOP            0x04
#define PTLLND_MSG_TYPE_HELLO           0x05

