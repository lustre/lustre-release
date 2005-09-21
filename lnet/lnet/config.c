/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2005 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
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
 */

#define DEBUG_SUBSYSTEM S_PORTALS
#include <lnet/lib-lnet.h>

typedef struct {                                /* tmp struct for parsing routes */
	struct list_head   ptb_list;		/* stash on lists */
	int                ptb_size;		/* allocated size */
	char               ptb_text[0];		/* text buffer */
} lnet_text_buf_t;

static int lnet_tbnob = 0;			/* track text buf allocation */
#define LNET_MAX_TEXTBUF_NOB     (64<<10)	/* bound allocation */
#define LNET_SINGLE_TEXTBUF_NOB  (4<<10)

void 
lnet_syntax(char *name, char *str, int offset, int width)
{
        const char *dots = "................................"
                           "................................"
                           "................................"
                           "................................"
                           "................................"
                           "................................"
                           "................................"
                           "................................";
        const char *dashes = "--------------------------------"
                             "--------------------------------"
                             "--------------------------------"
                             "--------------------------------"
                             "--------------------------------"
                             "--------------------------------"
                             "--------------------------------"
                             "--------------------------------";
        
	LCONSOLE_ERROR("Error parsing '%s=\"%s\"'\n", name, str);
	LCONSOLE_ERROR("here...........%.*s..%.*s|%.*s|\n", 
                       (int)strlen(name), dots, offset, dots,
                       (width < 1) ? 0 : width - 1, dashes);
}

int 
lnet_issep (char c)
{
	switch (c) {
	case '\n':
	case '\r':
	case ';':
		return 1;
	default:
		return 0;
	}
}

int
lnet_iswhite (char c)
{
	switch (c) {
	case ' ':
	case '\t':
	case '\n':
	case '\r':
		return 1;
	default:
		return 0;
	}
}

char *
lnet_trimwhite(char *str)
{
	char *end;
	
	while (lnet_iswhite(*str))
		str++;
	
	end = str + strlen(str);
	while (end > str) {
		if (!lnet_iswhite(end[-1]))
			break;
		end--;
	}

	*end = 0;
	return str;
}

int
lnet_net_unique(__u32 net, struct list_head *nilist)
{
        struct list_head *tmp;
        lnet_ni_t        *ni;

        list_for_each (tmp, nilist) {
                ni = list_entry(tmp, lnet_ni_t, ni_list);

                if (PTL_NIDNET(ni->ni_nid) == net)
                        return 0;
        }
        
        return 1;
}

lnet_ni_t *
lnet_new_ni(__u32 net, struct list_head *nilist)
{
        lnet_ni_t *ni;

        if (!lnet_net_unique(net, nilist)) {
                LCONSOLE_ERROR("Duplicate network specified: %s\n",
                               libcfs_net2str(net));
                return NULL;
        }
        
        PORTAL_ALLOC(ni, sizeof(*ni));
        if (ni == NULL) {
                CERROR("Out of memory creating network %s\n",
                       libcfs_net2str(net));
                return NULL;
        }
        
        /* zero counters/flags, NULL pointers... */
        memset(ni, 0, sizeof(*ni));

        /* LND will fill in the address part of the NID */
        ni->ni_nid = PTL_MKNID(net, 0);
        CFS_INIT_LIST_HEAD(&ni->ni_txq);

        list_add_tail(&ni->ni_list, nilist);
        return ni;
}

int
lnet_parse_networks(struct list_head *nilist, char *networks)
{
	int        tokensize = strlen(networks) + 1;
        char      *tokens;
        char      *str;
        lnet_ni_t *ni;
        __u32      net;
        int        count = 0;

	if (strlen(networks) > LNET_SINGLE_TEXTBUF_NOB) {
		/* _WAY_ conservative */
		LCONSOLE_ERROR("Can't parse networks: string too long\n");
		return -EINVAL;
	}

        PORTAL_ALLOC(tokens, tokensize);
        if (tokens == NULL) {
                CERROR("Can't allocate net tokens\n");
		return -ENOMEM;
        }

        the_lnet.ln_network_tokens = tokens;
        the_lnet.ln_network_tokens_nob = tokensize;
        memcpy (tokens, networks, tokensize);
	str = tokens;
        
        /* Add in the loopback network */
        ni = lnet_new_ni(PTL_MKNET(LOLND, 0), nilist);
        if (ni == NULL)
                goto failed;
        
        while (str != NULL && *str != 0) {
                char      *comma = strchr(str, ',');
                char      *bracket = strchr(str, '(');
                int        niface;
		char      *iface;

                /* NB we don't check interface conflicts here; it's the LNDs
                 * responsibility (if it cares at all) */

                if (bracket == NULL ||
		    (comma != NULL && comma < bracket)) {

                        /* no interface list specified */

			if (comma != NULL)
				*comma++ = 0;
			net = libcfs_str2net(lnet_trimwhite(str));
			
			if (net == PTL_NIDNET(LNET_NID_ANY)) {
                                lnet_syntax("networks", networks, 
                                            str - tokens, strlen(str));
                                LCONSOLE_ERROR("Unrecognised network type\n");
                                goto failed;
                        }

                        if (PTL_NETTYP(net) != LOLND && /* loopback is implicit */
                            lnet_new_ni(net, nilist) == NULL)
                                goto failed;

			str = comma;
			continue;
		}

		*bracket = 0;
		net = libcfs_str2net(lnet_trimwhite(str));
		if (net == PTL_NIDNET(LNET_NID_ANY)) {
                        lnet_syntax("networks", networks,
                                    str - tokens, strlen(str));
                        goto failed;
                } 

                if (count++ > 0) {
                        LCONSOLE_ERROR("Only 1 network supported when "
                                       "'portals_compatible' is set\n");
                        goto failed;
                }

                ni = lnet_new_ni(net, nilist);
                if (ni == NULL)
                        goto failed;

                niface = 0;
		iface = bracket + 1;

		bracket = strchr(iface, ')');
		if (bracket == NULL) {
                        lnet_syntax("networks", networks,
                                    iface - tokens, strlen(iface));
                        goto failed;
		}

		*bracket = 0;
		do {
			comma = strchr(iface, ',');
			if (comma != NULL)
				*comma++ = 0;
			
			iface = lnet_trimwhite(iface);
			if (*iface == 0) {
                                lnet_syntax("networks", networks, 
                                            iface - tokens, strlen(iface));
                                goto failed;
                        }

                        if (niface == LNET_MAX_INTERFACES) {
                                LCONSOLE_ERROR("Too many interfaces for net %s\n",
                                               libcfs_net2str(net));
                                goto failed;
                        }

                        ni->ni_interfaces[niface++] = iface;
			iface = comma;
		} while (iface != NULL);

		str = bracket + 1;
		comma = strchr(bracket + 1, ',');
		if (comma != NULL) {
			*comma = 0;
			str = lnet_trimwhite(str);
			if (*str != 0) {
                                lnet_syntax("networks", networks,
                                            str - tokens, strlen(str));
                                goto failed;
                        }
			str = comma + 1;
			continue;
		}
		
		str = lnet_trimwhite(str);
		if (*str != 0) {
                        lnet_syntax("networks", networks,
                                    str - tokens, strlen(str));
                        goto failed;
                }
	}

        LASSERT (!list_empty(nilist));
        return 0;

 failed:
        while (!list_empty(nilist)) {
                ni = list_entry(nilist->next, lnet_ni_t, ni_list);
                
                list_del(&ni->ni_list);
                PORTAL_FREE(ni, sizeof(*ni));
        }
	PORTAL_FREE(tokens, tokensize);
        the_lnet.ln_network_tokens = NULL;

        return -EINVAL;
}

lnet_text_buf_t *
lnet_new_text_buf (int str_len) 
{
	lnet_text_buf_t *ptb;
	int              nob;

	nob = offsetof(lnet_text_buf_t, ptb_text[str_len + 1]);
	if (nob > LNET_SINGLE_TEXTBUF_NOB) {
		/* _way_ conservative for "route net gateway..." */
		CERROR("text buffer too big\n");
		return NULL;
	}

	if (lnet_tbnob + nob > LNET_MAX_TEXTBUF_NOB) {
		CERROR("Too many text buffers\n");
		return NULL;
	}
	
	PORTAL_ALLOC(ptb, nob);
	if (ptb == NULL)
		return NULL;

	ptb->ptb_size = nob;
	lnet_tbnob += nob;
	return ptb;
}

void
lnet_free_text_buf (lnet_text_buf_t *ptb)
{
	PORTAL_FREE(ptb, ptb->ptb_size);
	lnet_tbnob -= ptb->ptb_size;
}

void
lnet_free_text_bufs(struct list_head *tbs)
{
	lnet_text_buf_t  *ptb;
	
	while (!list_empty(tbs)) {
		ptb = list_entry(tbs->next, lnet_text_buf_t, ptb_list);
		
		list_del(&ptb->ptb_list);
		lnet_free_text_buf(ptb);
	}
}

void
lnet_print_text_bufs(struct list_head *tbs)
{
	struct list_head *tmp;
	lnet_text_buf_t   *ptb;

	list_for_each (tmp, tbs) {
		ptb = list_entry(tmp, lnet_text_buf_t, ptb_list);

		CDEBUG(D_WARNING, "%s\n", ptb->ptb_text);
	}

	CDEBUG(D_WARNING, "%d allocated\n", lnet_tbnob);
}

int
lnet_str2tbs_sep (struct list_head *tbs, char *str) 
{
	struct list_head  pending;
	char             *sep;
	int               nob;
        int               i;
	lnet_text_buf_t   *ptb;

	INIT_LIST_HEAD(&pending);

	/* Split 'str' into separate commands */
	for (;;) {
                /* skip leading whitespace */
                while (lnet_iswhite(*str))
                        str++;
                
		/* scan for separator or comment */
		for (sep = str; *sep != 0; sep++)
			if (lnet_issep(*sep) || *sep == '#')
				break;

		nob = sep - str;
		if (nob > 0) {
			ptb = lnet_new_text_buf(nob + 1);
			if (ptb == NULL) {
				lnet_free_text_bufs(&pending);
				return -1;
			}
			
                        for (i = 0; i < nob; i++)
                                if (lnet_iswhite(str[i]))
                                        ptb->ptb_text[i] = ' ';
                                else
                                        ptb->ptb_text[i] = str[i];

			ptb->ptb_text[nob] = 0;

			list_add_tail(&ptb->ptb_list, &pending);
		}

		if (*sep == '#') {
			/* scan for separator */
			do {
				sep++;
			} while (*sep != 0 && !lnet_issep(*sep));
		}
		
		if (*sep == 0)
			break;

		str = sep + 1;
	}

	list_splice(&pending, tbs->prev);
	return 0;
}

int
lnet_expand1tb (struct list_head *list, 
	       char *str, char *sep1, char *sep2, 
	       char *item, int itemlen)
{
	int             len1 = sep1 - str;
	int             len2 = strlen(sep2 + 1);
	lnet_text_buf_t *ptb;

	LASSERT (*sep1 == '[');
	LASSERT (*sep2 == ']');

	ptb = lnet_new_text_buf(len1 + itemlen + len2 + 1);
	if (ptb == NULL)
		return -ENOMEM;
	
	memcpy(ptb->ptb_text, str, len1);
	memcpy(&ptb->ptb_text[len1], item, itemlen);
	memcpy(&ptb->ptb_text[len1+itemlen], sep2 + 1, len2);
	ptb->ptb_text[len1 + itemlen + len2] = 0;
	
	list_add_tail(&ptb->ptb_list, list);
	return 0;
}

int
lnet_str2tbs_expand (struct list_head *tbs, char *str)
{
	char              num[16];
	struct list_head  pending;
	char             *sep;
	char             *sep2;
	char             *parsed;
	char             *enditem;
	int               lo;
	int               hi;
	int               stride;
	int               i;
	int               nob;
	int               scanned;

	INIT_LIST_HEAD(&pending);
	
	sep = strchr(str, '[');
	if (sep == NULL)			/* nothing to expand */
		return 0;

        sep2 = strchr(sep, ']');
        if (sep2 == NULL)
                goto failed;

	for (parsed = sep; parsed < sep2; parsed = enditem) {

		enditem = ++parsed;
		while (enditem < sep2 && *enditem != ',')
			enditem++;

		if (enditem == parsed)		/* no empty items */
			goto failed;

                if (sscanf(parsed, "%d-%d/%d%n", &lo, &hi, &stride, &scanned) < 3) {

			if (sscanf(parsed, "%d-%d%n", &lo, &hi, &scanned) < 2) {

				/* simple string enumeration */
				if (lnet_expand1tb(&pending, str, sep, sep2,
                                                   parsed, enditem - parsed) != 0)
					goto failed;
				
				continue;
			}
			
			stride = 1;
		}

		/* range expansion */

		if (enditem != parsed + scanned) /* no trailing junk */
			goto failed;
                        
		if (hi < 0 || lo < 0 || stride < 0 || hi < lo || 
		    (hi - lo) % stride != 0)
			goto failed;
                        
		for (i = lo; i <= hi; i += stride) {

			snprintf(num, sizeof(num), "%d", i);
			nob = strlen(num);
			if (nob + 1 == sizeof(num))
				goto failed;
			
			if (lnet_expand1tb(&pending, str, sep, sep2, 
                                           num, nob) != 0)
				goto failed;
		}
	}
		
	list_splice(&pending, tbs->prev);
	return 1;
	
 failed:
	lnet_free_text_bufs(&pending);
	return -1;
}

int
lnet_parse_hops (char *str, unsigned int *hops)
{
        int     len = strlen(str);
        int     nob = len;
        
        return (sscanf(str, "%u%n", hops, &nob) >= 1 &&
                nob == len &&
                *hops > 0 && *hops < 256);
}


int
lnet_parse_route (char *str)
{
	/* static scratch buffer OK (single threaded) */
	static char       cmd[LNET_SINGLE_TEXTBUF_NOB];

	struct list_head  nets;
	struct list_head  gateways;
	struct list_head *tmp1;
	struct list_head *tmp2;
	__u32             net;
	lnet_nid_t        nid;
	lnet_text_buf_t   *ptb;
	int               rc;
	char             *sep;
	char             *token = str;
	int               ntokens = 0;
        int               myrc = -1;
        unsigned int      hops;
        int               got_hops = 0;

	INIT_LIST_HEAD(&gateways);
	INIT_LIST_HEAD(&nets);

	/* save a copy of the string for error messages */
	strncpy(cmd, str, sizeof(cmd) - 1);
	cmd[sizeof(cmd) - 1] = 0;

	sep = str;
	for (;;) {
		/* scan for token start */
		while (lnet_iswhite(*sep))
			sep++;
		if (*sep == 0) {
			if (ntokens < (got_hops ? 3 : 2))
                                goto token_error;
			break;
		}

		ntokens++;
		token = sep++;

		/* scan for token end */
		while (*sep != 0 && !lnet_iswhite(*sep))
			sep++;
		if (*sep != 0)
			*sep++ = 0;
		
		if (ntokens == 1) {
			tmp2 = &nets;		/* expanding nets */
                } else if (ntokens == 2 &&
                           lnet_parse_hops(token, &hops)) {
                        got_hops = 1;           /* got a hop count */
                        continue;
                } else {
			tmp2 = &gateways;	/* expanding gateways */
                }
                
		ptb = lnet_new_text_buf(strlen(token));
		if (ptb == NULL)
			goto out;

		strcpy(ptb->ptb_text, token);
		tmp1 = &ptb->ptb_list;
		list_add_tail(tmp1, tmp2);
		
		while (tmp1 != tmp2) {
			ptb = list_entry(tmp1, lnet_text_buf_t, ptb_list);

			rc = lnet_str2tbs_expand(tmp1->next, ptb->ptb_text);
			if (rc < 0)
				goto token_error;

			tmp1 = tmp1->next;
			
			if (rc > 0) {		/* expanded! */
				list_del(&ptb->ptb_list);
				lnet_free_text_buf(ptb);
				continue;
			}

			if (ntokens == 1) {
				net = libcfs_str2net(ptb->ptb_text);
				if (net == PTL_NIDNET(LNET_NID_ANY))
					goto token_error;
			} else {
				nid = libcfs_str2nid(ptb->ptb_text);
				if (nid == LNET_NID_ANY)
					goto token_error;
			}
		}
	}

        if (!got_hops)
                hops = 1;

	LASSERT (!list_empty(&nets));
	LASSERT (!list_empty(&gateways));

	list_for_each (tmp1, &nets) {
		ptb = list_entry(tmp1, lnet_text_buf_t, ptb_list);
		net = libcfs_str2net(ptb->ptb_text);
		LASSERT (net != PTL_NIDNET(LNET_NID_ANY));

		list_for_each (tmp2, &gateways) {
			ptb = list_entry(tmp2, lnet_text_buf_t, ptb_list);
			nid = libcfs_str2nid(ptb->ptb_text);
			LASSERT (nid != LNET_NID_ANY);

                        rc = lnet_add_route (net, hops, nid);
                        if (rc != 0) {
                                CERROR("Can't create route "
                                       "to %s via %s\n",
                                       libcfs_net2str(net),
                                       libcfs_nid2str(nid));
                                goto out;
                        }
		}
	}

        myrc = 0;
        goto out;
        
 token_error:
	lnet_syntax("routes", cmd, token - str, strlen(token));
 out:
	lnet_free_text_bufs(&nets);
	lnet_free_text_bufs(&gateways);
	return myrc;
}

int
lnet_parse_route_tbs(struct list_head *tbs)
{
	lnet_text_buf_t   *ptb;

	while (!list_empty(tbs)) {
		ptb = list_entry(tbs->next, lnet_text_buf_t, ptb_list);

		if (lnet_parse_route(ptb->ptb_text) < 0) {
			lnet_free_text_bufs(tbs);
			return -EINVAL;
		}

		list_del(&ptb->ptb_list);
		lnet_free_text_buf(ptb);
	}

        return 0;
}

int
lnet_parse_routes (char *routes)
{
	struct list_head  tbs;
	int               rc = 0;

        if (the_lnet.ln_ptlcompat > 0 && 
            routes[0] != 0) {
                /* Can't route when running in compatibility mode */
                LCONSOLE_ERROR("Route tables are not supported when "
                               "'portals_compatible' is set\n");
                return -EINVAL;
        }
        
	INIT_LIST_HEAD(&tbs);

	if (lnet_str2tbs_sep(&tbs, routes) < 0) {
		CERROR("Error parsing routes\n");
		rc = -EINVAL;
	} else {
                rc = lnet_parse_route_tbs(&tbs);
        }

	LASSERT (lnet_tbnob == 0);
	return rc;
}

#ifdef __KERNEL__
int
lnet_set_ip_niaddr (lnet_ni_t *ni) 
{
        __u32  net = PTL_NIDNET(ni->ni_nid);
        char **names;
        int    n;
        __u32  ip;
        __u32  netmask;
        int    up;
        int    i;
        int    rc;

        /* Convenience for LNDs that use the IP address of a local interface as
         * the local address part of their NID */

        if (ni->ni_interfaces[0] != NULL) {

                CLASSERT (LNET_MAX_INTERFACES > 1);

                if (ni->ni_interfaces[1] != NULL) {
                        CERROR("Net %s doesn't support multiple interfaces\n",
                               libcfs_net2str(net));
                        return -EPERM;
                }
                
                rc = libcfs_ipif_query(ni->ni_interfaces[0],
                                       &up, &ip, &netmask);
                if (rc != 0) {
                        CERROR("Net %s can't query interface %s: %d\n",
                               libcfs_net2str(net), ni->ni_interfaces[0], rc);
                        return -EPERM;
                }

                if (!up) {
                        CERROR("Net %s can't use interface %s: it's down\n",
                               libcfs_net2str(net), ni->ni_interfaces[0]);
                        return -ENETDOWN;
                }
                
                ni->ni_nid = PTL_MKNID(net, ip);
                return 0;
        }

        n = libcfs_ipif_enumerate(&names);
        if (n <= 0) {
                CERROR("Net %s can't enumerate interfaces: %d\n", 
                       libcfs_net2str(net), n);
                return 0;
        }

        for (i = 0; i < n; i++) {
                if (!strcmp(names[i], "lo")) /* skip the loopback IF */
                        continue;
                
                rc = libcfs_ipif_query(names[i], &up, &ip, &netmask);
                
                if (rc != 0) {
                        CWARN("Net %s can't query interface %s: %d\n",
                              libcfs_net2str(net), names[i], rc);
                        continue;
                }
                        
                if (!up) {
                        CWARN("Net %s ignoring interface %s (down)\n",
                              libcfs_net2str(net), names[i]);
                        continue;
                }

                libcfs_ipif_free_enumeration(names, n);
                ni->ni_nid = PTL_MKNID(net, ip);
                return 0;
        }

        CERROR("Net %s can't find any interfaces\n", libcfs_net2str(net));
        libcfs_ipif_free_enumeration(names, n);
        return -ENOENT;
}

EXPORT_SYMBOL(lnet_set_ip_niaddr);

#endif
