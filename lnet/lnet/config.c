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
ptl_nis_conflict(ptl_ni_t *ni1, ptl_ni_t *ni2)
{
        int               i;
        int               j;

        if (PTL_NETNAL(PTL_NIDNET(ni1->ni_nid)) != /* different NALs */
            PTL_NETNAL(PTL_NIDNET(ni2->ni_nid)))
                return 0;

        if (ni1 != ni2 &&
            PTL_NIDNET(ni1->ni_nid) == PTL_NIDNET(ni2->ni_nid)) {
                CERROR("Duplicate network: %s\n",
                       libcfs_net2str(PTL_NIDNET(ni1->ni_nid)));
                return 1;
        }

        if (ni1->ni_interfaces[0] == NULL ||   
            ni2->ni_interfaces[0] == NULL) {
                /* one (or both) using all available interfaces */
                if (ni1 != ni2) {
                        CERROR("Interface conflict: %s, %s\n",
                               libcfs_net2str(PTL_NIDNET(ni1->ni_nid)),
                               libcfs_net2str(PTL_NIDNET(ni2->ni_nid)));
                        return 1;
                }
                return 0;
        }
        
        for (i = 0; i < PTL_MAX_INTERFACES; i++) {
                if (ni1->ni_interfaces[i] == NULL)
                        break;

                for (j = 0; j < PTL_MAX_INTERFACES; j++) {
                        if (ni2->ni_interfaces[j] == NULL)
                                break;

                        if (ni1 == ni2 && i == j)
                                continue;

                        if (strcmp(ni1->ni_interfaces[i],
                                   ni2->ni_interfaces[j]))
                                continue;
                        
                        CERROR("Duplicate interface: %s(%s), %s(%s)\n",
                               libcfs_net2str(PTL_NIDNET(ni1->ni_nid)),
                               ni1->ni_interfaces[i],
                               libcfs_net2str(PTL_NIDNET(ni2->ni_nid)),
                               ni2->ni_interfaces[i]);
                        return 1;
                }
        }
        
        return 0;
}

ptl_err_t
ptl_check_ni_conflicts(ptl_ni_t *ni, struct list_head *nilist)
{
        struct list_head *tmp;
        ptl_ni_t         *ni2;

        /* Yes! ni just added to this list.  
         * Check its network is unique and its interfaces don't conflict */
        LASSERT (ni == list_entry(nilist->prev, ptl_ni_t, ni_list));
        
        list_for_each (tmp, nilist) {
                ni2 = list_entry(tmp, ptl_ni_t, ni_list);

                if (ptl_nis_conflict(ni, ni2))
                        return PTL_FAIL;
        }
        
        return PTL_OK;
}

ptl_err_t
ptl_parse_networks(struct list_head *nilist, char *networks)
{
	int       tokensize = strlen(networks) + 1;
        char     *tokens;
        char     *str;
        ptl_ni_t *ni = NULL;
        __u32     net;
        int       rc;

	if (strlen(networks) > PAGE_SIZE) {
		/* _WAY_ conservative */
		CERROR("Can't parse networks; string too long\n");
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

        while (str != NULL && *str != 0) {
                char      *comma = strchr(str, ',');
                char      *bracket = strchr(str, '(');
                int        niface;
		char      *iface;

                PORTAL_ALLOC(ni, sizeof(*ni));
                if (ni == NULL) {
                        CERROR ("ENOMEM parsing 'networks=\"%s\"'\n", networks);
                        goto failed;
                }
                /* zero counters/flags, NULL pointers... */
                memset(ni, 0, sizeof(*ni));
                list_add_tail(&ni->ni_list, nilist);
                
                if (bracket == NULL ||
		    (comma != NULL && comma < bracket)) {
			if (comma != NULL)
				*comma++ = 0;
			net = libcfs_str2net(ptl_trimwhite(str));
			
			if (net == PTL_NIDNET(PTL_NID_ANY)) {
                                ptl_syntax("networks", networks, 
                                           str - tokens, strlen(str));
                                goto failed;
                        }

                        ni->ni_nid = PTL_MKNID(net, 0);
                        if (ptl_check_ni_conflicts(ni, nilist) != PTL_OK)
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

                ni->ni_nid = PTL_MKNID(net, 0);

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
                                LCONSOLE_ERROR("Too many interfaces for %s\n",
                                               libcfs_net2str(PTL_NIDNET(ni->ni_nid)));
                                goto failed;
                        }

                        ni->ni_interfaces[niface++] = iface;
			iface = comma;
		} while (iface != NULL);

                if (ptl_check_ni_conflicts(ni, nilist) != PTL_OK)
                        goto failed;
                
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
	if (nob > PAGE_SIZE) {
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
	ptl_text_buf_t   *ptb;

	INIT_LIST_HEAD(&pending);

	/* Split 'str' into separate commands */
	for (;;) {
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
			
			memcpy(ptb->ptb_text, str, nob);
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
ptl_str2tbs_expand (struct list_head *tbs, char *str)
{
	struct list_head  pending;
	char             *sep;
	int               nob;
	ptl_text_buf_t   *ptb;
	int               lo;
	int               hi;
	int               stride;
	int               i;
	int               scanned;
	int               scanned2;

	INIT_LIST_HEAD(&pending);
	
	sep = strchr(str, '[');
	if (sep == NULL)			/* nothing to expand */
		return 0;
		
	/* check it's a valid range... */
	nob = sep - str;

	if (sscanf(sep + 1, "%d-%d%n", &lo, &hi, &scanned) < 2)
		goto failed;

	if (sep[1 + scanned] != '/')
		stride = 1;
	else if (sscanf(sep + 1 + scanned + 1, "%d%n", &stride, &scanned2) < 1)
		goto failed;
	else
		scanned += 1 + scanned2;
	
	if (sep[scanned + 1] != ']')
		goto failed;

	if (hi < 0 || lo < 0 || stride < 0 || hi < lo || 
	    (hi - lo) % stride != 0)
		goto failed;

	/* ...and expand it */
	for (i = lo; i <= hi; i += stride) {
		char            num[16];
		ptl_text_buf_t *ptb;

		snprintf(num, sizeof(num), "%d", i);
		if (strlen(num) == sizeof(num) - 1)
			goto failed;

		ptb = ptl_new_text_buf(nob + strlen(num) + 
				      strlen(sep + 1 + scanned + 1));
		if (ptb == NULL)
			goto failed;
			
		memcpy(ptb->ptb_text, str, sep - str);
		strcpy(&ptb->ptb_text[nob], num);
		strcat(&ptb->ptb_text[nob], &sep[1 + scanned + 1]);

		list_add_tail(&ptb->ptb_list, &pending);
	}

	list_splice(&pending, tbs->prev);
	return (hi + 1 - lo);
	
 failed:
	ptl_free_text_bufs(&pending);
	return -1;
}

int
ptl_parse_route (char *str)
{
	/* static scratch buffer OK (single threaded) */
	static char      cmd[PAGE_SIZE];

	struct list_head gateways;
	__u32            net = 0;		/* avoid a warning */
	ptl_nid_t        nid;
	ptl_text_buf_t  *ptb;
	ptl_text_buf_t  *tb2;
	int              rc;
	char            *sep;
	char            *token;
	int              ntokens = 0;

	INIT_LIST_HEAD(&gateways);

	/* save a copy of the string for error messages */
	strncpy(cmd, str, sizeof(cmd) - 1);
	cmd[sizeof(cmd) - 1] = 0;

	sep = str;
	for (;;) {
		/* scan for token start */
		while (ptl_iswhite(*sep))
			sep++;
		if (*sep == 0) {
			if (ntokens < 3) {
				ptl_syntax("routes", cmd, sep - str, -1);
				return -1;
			}
			return 0;
		}

		ntokens++;
		token = sep++;

		/* scan for token end */
		while (*sep != 0 && !ptl_iswhite(*sep))
			sep++;
		if (*sep != 0)
			*sep++ = 0;
		
		if (ntokens == 1) {
			if (!strcmp(token, "route"))
				continue;
			goto token_error;
		}
			
		if (ntokens == 2) {
			net = libcfs_str2net(token);
			if (net != PTL_NIDNET(PTL_NID_ANY))
				continue;
			goto token_error;
		}

		ptb = ptl_new_text_buf(strlen(token));
		if (ptb == NULL) {
			CERROR ("Error parsing routes\n");
			return -1;
		}

		strcpy(ptb->ptb_text, token);

		list_add (&ptb->ptb_list, &gateways);
		while (!list_empty(&gateways)) {
			ptb = list_entry(gateways.next, 
					ptl_text_buf_t, ptb_list);

			/* Add ptb's expansions right after it */
			rc = ptl_str2tbs_expand(ptb->ptb_list.next, 
						ptb->ptb_text);
			if (rc < 0)
				goto token_error;
		
			if (rc == 0) {
				/* no expansions: check gateway nid */
				nid = libcfs_str2nid(ptb->ptb_text);
				if (nid == PTL_NID_ANY)
					goto token_error;

				rc = kpr_add_route (net, nid);
				if (rc != 0) {
					CERROR("Can't create route "
					       "to %s via %s\n",
					       libcfs_net2str(net),
					       libcfs_nid2str(nid));
					goto error;
				}
			}

			list_del(&ptb->ptb_list);
			ptl_free_text_buf(ptb);
		}
	}

 token_error:
	ptl_syntax("routes", cmd, token - str, strlen(token));
 error:
	ptl_free_text_bufs(&gateways);
	return -1;
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

ptl_err_t
ptl_read_route_table (char *fname) 
{
        int rc = PTL_FAIL;
        
        /* read chunks into a page buffer
         * ptl_str2tbs_sep(buffer)
         * if last tb is partial, copy to start of buffer
         * and read next chunk from there
         * then just ptl_parse_route_tbs() 
         */

	LASSERT (ptl_tbnob == 0);
        return rc;
}

