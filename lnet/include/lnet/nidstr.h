#ifndef _LNET_NIDSTRINGS_H
#define _LNET_NIDSTRINGS_H
#include <lnet/types.h>

struct list_head;

#define LNET_NIDSTR_COUNT  1024    /* # of nidstrings */
#define LNET_NIDSTR_SIZE   32      /* size of each one (see below for usage) */

/* support decl needed both by kernel and liblustre */
int libcfs_isknown_lnd(int type);
char *libcfs_lnd2modname(int type);
char *libcfs_lnd2str(int type);
int libcfs_str2lnd(const char *str);
char *libcfs_net2str(__u32 net);
char *libcfs_nid2str(lnet_nid_t nid);
__u32 libcfs_str2net(const char *str);
lnet_nid_t libcfs_str2nid(const char *str);
int libcfs_str2anynid(lnet_nid_t *nid, const char *str);
char *libcfs_id2str(lnet_process_id_t id);
void cfs_free_nidlist(struct list_head *list);
int cfs_parse_nidlist(char *str, int len, struct list_head *list);
int cfs_print_nidlist(char *buffer, int count, struct list_head *list);
int cfs_match_nid(lnet_nid_t nid, struct list_head *list);
bool cfs_nidrange_is_contiguous(struct list_head *nidlist);
void cfs_nidrange_find_min_max(struct list_head *nidlist, char *min_nid,
			       char *max_nid, int nidstr_length);
void libcfs_init_nidstrings(void);

#endif /* _LNET_NIDSTRINGS_H */
