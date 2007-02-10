#define DEBUG_SUBSYSTEM S_PINGER

#include <libcfs/kp30.h>
#include <lnet/lnet.h>

#define UT_PORTAL       42

#define PJK_UT_MSG(fmt...) do{printk("<1>" UT_MSG_MODULE_NAME ":%-30s:",__FUNCTION__);printk(fmt);}while(0)

#define DO_TYPE(x) case x: return #x;

const char *get_ev_type_string(int evtype)
{
        switch(evtype)
        {
                DO_TYPE(LNET_EVENT_GET);
                DO_TYPE(LNET_EVENT_PUT);
                DO_TYPE(LNET_EVENT_REPLY);
                DO_TYPE(LNET_EVENT_ACK);
                DO_TYPE(LNET_EVENT_SEND);
                DO_TYPE(LNET_EVENT_UNLINK);
        default:
                return "";
        }
}

static volatile int seen = 0;
static volatile int seen_unlink = 0;

static inline void handler(lnet_event_t *ev)
{
        PJK_UT_MSG("-------- EVENT START ------------\n");
        PJK_UT_MSG("type=%d %s\n",ev->type,get_ev_type_string(ev->type));
        PJK_UT_MSG("portal=%d\n",ev->pt_index);
        PJK_UT_MSG("matchbits="LPX64"\n",ev->match_bits);
        PJK_UT_MSG("request length=%d\n",ev->rlength);
        PJK_UT_MSG("manipulated length=%d\n",ev->mlength);
        PJK_UT_MSG("offset=%d\n",ev->offset);
        PJK_UT_MSG("status=%d\n",ev->status);
        PJK_UT_MSG("unlinked=%d\n",ev->unlinked);
        PJK_UT_MSG("md.user_ptr=%p\n",ev->md.user_ptr);
        PJK_UT_MSG("-------- EVENT END --------------\n");
        ++seen;
        if(ev->unlinked)++seen_unlink;
}
