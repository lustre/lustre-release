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
#include <portals/lib-p30.h>

typedef struct {                                /* tmp struct for parsing routes */
	struct list_head   ptb_list;		/* stash on lists */
	int                ptb_size;		/* allocated size */
	char               ptb_text[0];		/* text buffer */
} ptl_text_buf_t;

static int ptl_tbnob = 0;			/* track text buf allocation */
#define PTL_MAX_TEXTBUF_NOB     (64<<10)	/* bound allocation */
#define PTL_SINGLE_TEXTBUF_NOB  (4<<10)

void 
ptl_syntax(char *name, char *str, int offset, int width)
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
ptl_issep (char c)
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
ptl_iswhite (char c)
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
ptl_trimwhite(char *str)
{
	char *end;
	
	while (ptl_iswhite(*str))
		str++;
	
	end = str + strlen(str);
	while (end > str) {
		if (!ptl_iswhite(end[-1]))
			break;
		end--;
	}

	*end = 0;
	return str;
}

int
ptl_net_unique(__u32 net, struct list_head *nilist)
{
        struct list_head *tmp;
        ptl_ni_t         *ni;

        list_for_each (tmp, nilist) {
                ni = list_entry(tmp, ptl_ni_t, ni_list);

                if (PTL_NIDNET(ni->ni_nid) == net)
                        return 0;
        }
        
        return 1;
}

ptl_ni_t *
ptl_new_ni(__u32 net, struct list_head *nilist)
{
        ptl_ni_t *ni;

        if (!ptl_net_unique(net, nilist)) {
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

        /* NAL will fill in the address part of the NID */
        ni->ni_nid = PTL_MKNID(net, 0);

        list_add_tail(&ni->ni_list, nilist);
        return ni;
}

ptl_err_t
ptl_parse_networks(struct list_head *nilist, char *networks)
{
	int       tokensize = strlen(networks) + 1;
        char     *tokens;
        char     *str;
        ptl_ni_t *ni;
        __u32     net;

	if (strlen(networks) > PTL_SINGLE_TEXTBUF_NOB) {
		/* _WAY_ conservative */
		LCONSOLE_ERROR("Can't parse networks: string too long\n");
		return PTL_FAIL;
	}

        PORTAL_ALLOC(tokens, tokensize);
        if (tokens == NULL) {
                CERROR("Can't allocate net tokens\n");
		return PTL_FAIL;
        }

        ptl_apini.apini_network_tokens = tokens;
        ptl_apini.apini_network_tokens_nob = tokensize;
        memcpy (tokens, networks, tokensize);
	str = tokens;
        
        /* Add in the loopback network */
        ni = ptl_new_ni(PTL_MKNET(LONAL, 0), nilist);
        if (ni == NULL)
                goto failed;
        
        while (str != NULL && *str != 0) {
                char      *comma = strchr(str, ',');
                char      *bracket = strchr(str, '(');
                int        niface;
		char      *iface;

                /* NB we don't check interface conflicts here; it's the NALs
                 * responsibility (if it cares at all) */

                if (bracket == NULL ||
		    (comma != NULL && comma < bracket)) {

                        /* no interface list specified */

			if (comma != NULL)
				*comma++ = 0;
			net = libcfs_str2net(ptl_trimwhite(str));
			
			if (net == PTL_NIDNET(PTL_NID_ANY)) {
                                ptl_syntax("networks", networks, 
                                           str - tokens, strlen(str));
                                goto failed;
                        }

                        if (ptl_new_ni(net, nilist) == NULL)
                                goto failed;

			str = comma;
			continue;
		}

		*bracket = 0;
		net = libcfs_str2net(ptl_trimwhite(str));
		if (net == PTL_NIDNET(PTL_NID_ANY)) {
                        ptl_syntax("networks", networks,
                                   str - tokens, strlen(str));
                        goto failed;
                } 

                ni = ptl_new_ni(net, nilist);
                if (ni == NULL)
                        goto failed;

                niface = 0;
		iface = bracket + 1;

		bracket = strchr(iface, ')');
		if (bracket == NULL) {
                        ptl_syntax ("networks", networks,
                                    iface - tokens, strlen(iface));
                        goto failed;
		}

		*bracket = 0;
		do {
			comma = strchr(iface, ',');
			if (comma != NULL)
				*comma++ = 0;
			
			iface = ptl_trimwhite(iface);
			if (*iface == 0) {
                                ptl_syntax("networks", networks, 
                                           iface - tokens, strlen(iface));
                                goto failed;
                        }

                        if (niface == PTL_MAX_INTERFACES) {
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
			str = ptl_trimwhite(str);
			if (*str != 0) {
                                ptl_syntax ("networks", networks,
                                            str - tokens, strlen(str));
                                goto failed;
                        }
			str = comma + 1;
			continue;
		}
		
		str = ptl_trimwhite(str);
		if (*str != 0) {
                        ptl_syntax ("networks", networks,
                                    str - tokens, strlen(str));
                        goto failed;
                }
	}

        if (list_empty(nilist)) {
                LCONSOLE_ERROR("No networks specified\n");
                goto failed;
        }
        return PTL_OK;

 failed:
        while (!list_empty(nilist)) {
                ni = list_entry(nilist->next, ptl_ni_t, ni_list);
                
                list_del(&ni->ni_list);
                PORTAL_FREE(ni, sizeof(*ni));
        }
	PORTAL_FREE(tokens, tokensize);
        ptl_apini.apini_network_tokens = NULL;

        return PTL_FAIL;
}

ptl_text_buf_t *
ptl_new_text_buf (int str_len) 
{
	ptl_text_buf_t *ptb;
	int             nob;

	nob = offsetof(ptl_text_buf_t, ptb_text[str_len + 1]);
	if (nob > PTL_SINGLE_TEXTBUF_NOB) {
		/* _way_ conservative for "route net gateway..." */
		CERROR("text buffer too big\n");
		return NULL;
	}

	if (ptl_tbnob + nob > PTL_MAX_TEXTBUF_NOB) {
		CERROR("Too many text buffers\n");
		return NULL;
	}
	
	PORTAL_ALLOC(ptb, nob);
	if (ptb == NULL)
		return NULL;

	ptb->ptb_size = nob;
	ptl_tbnob += nob;
	return ptb;
}

void
ptl_free_text_buf (ptl_text_buf_t *ptb)
{
	PORTAL_FREE(ptb, ptb->ptb_size);
	ptl_tbnob -= ptb->ptb_size;
}

void
ptl_free_text_bufs(struct list_head *tbs)
{
	ptl_text_buf_t  *ptb;
	
	while (!list_empty(tbs)) {
		ptb = list_entry(tbs->next, ptl_text_buf_t, ptb_list);
		
		list_del(&ptb->ptb_list);
		ptl_free_text_buf(ptb);
	}
}

void
ptl_print_text_bufs(struct list_head *tbs)
{
	struct list_head *tmp;
	ptl_text_buf_t   *ptb;

	list_for_each (tmp, tbs) {
		ptb = list_entry(tmp, ptl_text_buf_t, ptb_list);

		CDEBUG(D_WARNING, "%s\n", ptb->ptb_text);
	}

	CDEBUG(D_WARNING, "%d allocated\n", ptl_tbnob);
}

int
ptl_str2tbs_sep (struct list_head *tbs, char *str) 
{
	struct list_head  pending;
	char             *sep;
	int               nob;
        int               i;
	ptl_text_buf_t   *ptb;

	INIT_LIST_HEAD(&pending);

	/* Split 'str' into separate commands */
	for (;;) {
                /* skip leading whitespace */
                while (ptl_iswhite(*str))
                        str++;
                
		/* scan for separator or comment */
		for (sep = str; *sep != 0; sep++)
			if (ptl_issep(*sep) || *sep == '#')
				break;

		nob = sep - str;
		if (nob > 0) {
			ptb = ptl_new_text_buf(nob + 1);
			if (ptb == NULL) {
				ptl_free_text_bufs(&pending);
				return -1;
			}
			
                        for (i = 0; i < nob; i++)
                                if (ptl_iswhite(str[i]))
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
			} while (*sep != 0 && !ptl_issep(*sep));
		}
		
		if (*sep == 0)
			break;

		str = sep + 1;
	}

	list_splice(&pending, tbs->prev);
	return 0;
}

int
ptl_expand1tb (struct list_head *list, 
	       char *str, char *sep1, char *sep2, 
	       char *item, int itemlen)
{
	int             len1 = sep1 - str;
	int             len2 = strlen(sep2 + 1);
	ptl_text_buf_t *ptb;

	LASSERT (*sep1 == '[');
	LASSERT (*sep2 == ']');

	ptb = ptl_new_text_buf(len1 + itemlen + len2 + 1);
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
ptl_str2tbs_expand (struct list_head *tbs, char *str)
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
				if (ptl_expand1tb(&pending, str, sep, sep2,
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
			
			if (ptl_expand1tb(&pending, str, sep, sep2, 
					  num, nob) != 0)
				goto failed;
		}
	}
		
	list_splice(&pending, tbs->prev);
	return 1;
	
 failed:
	ptl_free_text_bufs(&pending);
	return -1;
}

int
ptl_parse_route (char *str)
{
	/* static scratch buffer OK (single threaded) */
	static char       cmd[PTL_SINGLE_TEXTBUF_NOB];

	struct list_head  nets;
	struct list_head  gateways;
	struct list_head *tmp1;
	struct list_head *tmp2;
	__u32             net;
	ptl_nid_t         nid;
	ptl_text_buf_t   *ptb;
	int               rc;
	char             *sep;
	char             *token = str;
	int               ntokens = 0;
        int               myrc = -1;

	INIT_LIST_HEAD(&gateways);
	INIT_LIST_HEAD(&nets);

	/* save a copy of the string for error messages */
	strncpy(cmd, str, sizeof(cmd) - 1);
	cmd[sizeof(cmd) - 1] = 0;

	sep = str;
	for (;;) {
		/* scan for token start */
		while (ptl_iswhite(*sep))
			sep++;
		if (*sep == 0) {
			if (ntokens < 2)
                                goto token_error;
			break;
		}

		ntokens++;
		token = sep++;

		/* scan for token end */
		while (*sep != 0 && !ptl_iswhite(*sep))
			sep++;
		if (*sep != 0)
			*sep++ = 0;
		
		if (ntokens == 1)
			tmp2 = &nets;		/* expanding nets */
		else
			tmp2 = &gateways;	/* expanding gateways */
			
		ptb = ptl_new_text_buf(strlen(token));
		if (ptb == NULL)
			goto out;

		strcpy(ptb->ptb_text, token);
		tmp1 = &ptb->ptb_list;
		list_add_tail(tmp1, tmp2);
		
		while (tmp1 != tmp2) {
			ptb = list_entry(tmp1, ptl_text_buf_t, ptb_list);

			rc = ptl_str2tbs_expand(tmp1->next, ptb->ptb_text);
			if (rc < 0)
				goto token_error;

			tmp1 = tmp1->next;
			
			if (rc > 0) {		/* expanded! */
				list_del(&ptb->ptb_list);
				ptl_free_text_buf(ptb);
				continue;
			}

			if (ntokens == 1) {
				net = libcfs_str2net(ptb->ptb_text);
				if (net == PTL_NIDNET(PTL_NID_ANY))
					goto token_error;
			} else {
				nid = libcfs_str2nid(ptb->ptb_text);
				if (nid == PTL_NID_ANY)
					goto token_error;
			}
		}
	}

	LASSERT (!list_empty(&nets));
	LASSERT (!list_empty(&gateways));

	list_for_each (tmp1, &nets) {
		ptb = list_entry(tmp1, ptl_text_buf_t, ptb_list);
		net = libcfs_str2net(ptb->ptb_text);
		LASSERT (net != PTL_NIDNET(PTL_NID_ANY));

		list_for_each (tmp2, &gateways) {
			ptb = list_entry(tmp2, ptl_text_buf_t, ptb_list);
			nid = libcfs_str2nid(ptb->ptb_text);
			LASSERT (nid != PTL_NID_ANY);

                        rc = kpr_add_route (net, nid);
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
	ptl_syntax("routes", cmd, token - str, strlen(token));
 out:
	ptl_free_text_bufs(&nets);
	ptl_free_text_bufs(&gateways);
	return myrc;
}

ptl_err_t
ptl_parse_route_tbs(struct list_head *tbs)
{
	ptl_text_buf_t   *ptb;

	while (!list_empty(tbs)) {
		ptb = list_entry(tbs->next, ptl_text_buf_t, ptb_list);

		if (ptl_parse_route(ptb->ptb_text) < 0) {
			ptl_free_text_bufs(tbs);
			return PTL_FAIL;
		}

		list_del(&ptb->ptb_list);
		ptl_free_text_buf(ptb);
	}

        return PTL_OK;
}

ptl_err_t
ptl_parse_routes (char *routes)
{
	struct list_head  tbs;
	int               rc = PTL_OK;

	INIT_LIST_HEAD(&tbs);

	if (ptl_str2tbs_sep(&tbs, routes) < 0) {
		CERROR("Error parsing routes\n");
		rc = PTL_FAIL;
	} else {
                rc = ptl_parse_route_tbs(&tbs);
        }

	LASSERT (ptl_tbnob == 0);
	return rc;
}

#ifdef __KERNEL__
ptl_err_t
ptl_set_ip_niaddr (ptl_ni_t *ni) 
{
        __u32  net = PTL_NIDNET(ni->ni_nid);
        char **names;
        int    n;
        __u32  ip;
        __u32  netmask;
        int    up;
        int    i;
        int    rc;

        /* Convenience for NALs that use the IP address of a local interface as
         * the local address part of their NID */

        if (ni->ni_interfaces[0] != NULL) {

                CLASSERT (PTL_MAX_INTERFACES > 1);

                if (ni->ni_interfaces[1] != NULL) {
                        CERROR("Net %s doesn't support multiple interfaces\n",
                               libcfs_net2str(net));
                        return PTL_FAIL;
                }
                
                rc = libcfs_ipif_query(ni->ni_interfaces[0],
                                       &up, &ip, &netmask);
                if (rc != 0) {
                        CERROR("Net %s can't query interface %s: %d\n",
                               libcfs_net2str(net), ni->ni_interfaces[0], rc);
                        return PTL_FAIL;
                }

                if (!up) {
                        CERROR("Net %s can't use interface %s: it's down\n",
                               libcfs_net2str(net), ni->ni_interfaces[0]);
                        return PTL_FAIL;
                }
                
                ni->ni_nid = PTL_MKNID(net, ip);
                return PTL_OK;
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
                return PTL_OK;
        }

        CERROR("Net %s can't find any interfaces\n", libcfs_net2str(net));
        libcfs_ipif_free_enumeration(names, n);
        return PTL_FAIL;
}

EXPORT_SYMBOL(ptl_set_ip_niaddr);

#endif
