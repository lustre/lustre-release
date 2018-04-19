/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <lnet/lib-lnet.h>

/* tmp struct for parsing routes */
struct lnet_text_buf {
	struct list_head	ltb_list;	/* stash on lists */
	int			ltb_size;	/* allocated size */
	char			ltb_text[0];	/* text buffer */
};

static int lnet_tbnob = 0;			/* track text buf allocation */
#define LNET_MAX_TEXTBUF_NOB	 (64<<10)	/* bound allocation */
#define LNET_SINGLE_TEXTBUF_NOB  (4<<10)

#define SPACESTR " \t\v\r\n"
#define DELIMITERS ":()[]"

static void
lnet_syntax(const char *name, const char *str, int offset, int width)
{
	static char dots[LNET_SINGLE_TEXTBUF_NOB];
	static char dashes[LNET_SINGLE_TEXTBUF_NOB];

	memset(dots, '.', sizeof(dots));
	dots[sizeof(dots)-1] = 0;
	memset(dashes, '-', sizeof(dashes));
	dashes[sizeof(dashes)-1] = 0;

	LCONSOLE_ERROR_MSG(0x10f, "Error parsing '%s=\"%s\"'\n", name, str);
	LCONSOLE_ERROR_MSG(0x110, "here...........%.*s..%.*s|%.*s|\n",
			   (int)strlen(name), dots, offset, dots,
			    (width < 1) ? 0 : width - 1, dashes);
}

static int
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

bool
lnet_net_unique(__u32 net_id, struct list_head *netlist,
		struct lnet_net **net)
{
	struct lnet_net  *net_l;

	if (!netlist)
		return true;

	list_for_each_entry(net_l, netlist, net_list) {
		if (net_l->net_id == net_id) {
			if (net != NULL)
				*net = net_l;
			return false;
		}
	}

	return true;
}

/* check that the NI is unique within the list of NIs already added to
 * a network */
bool
lnet_ni_unique_net(struct list_head *nilist, char *iface)
{
	struct list_head *tmp;
	struct lnet_ni *ni;

	list_for_each(tmp, nilist) {
		ni = list_entry(tmp, struct lnet_ni, ni_netlist);

		if (ni->ni_interfaces[0] != NULL &&
		    strncmp(ni->ni_interfaces[0], iface, strlen(iface)) == 0)
			return false;
	}

	return true;
}

/* check that the NI is unique to the interfaces with in the same NI.
 * This is only a consideration if use_tcp_bonding is set */
static bool
lnet_ni_unique_ni(char *iface_list[LNET_NUM_INTERFACES], char *iface)
{
	int i;
	for (i = 0; i < LNET_NUM_INTERFACES; i++) {
		if (iface_list[i] != NULL &&
		    strncmp(iface_list[i], iface, strlen(iface)) == 0)
			return false;
	}

	return true;
}

static bool
in_array(__u32 *array, __u32 size, __u32 value)
{
	int i;

	for (i = 0; i < size; i++) {
		if (array[i] == value)
			return false;
	}

	return true;
}

static int
lnet_net_append_cpts(__u32 *cpts, __u32 ncpts, struct lnet_net *net)
{
	__u32 *added_cpts = NULL;
	int i, j = 0, rc = 0;

	/*
	 * no need to go futher since a subset of the NIs already exist on
	 * all CPTs
	 */
	if (net->net_ncpts == LNET_CPT_NUMBER)
		return 0;

	if (cpts == NULL) {
		/* there is an NI which will exist on all CPTs */
		if (net->net_cpts != NULL)
			LIBCFS_FREE(net->net_cpts, sizeof(*net->net_cpts) *
				    net->net_ncpts);
		net->net_cpts = NULL;
		net->net_ncpts = LNET_CPT_NUMBER;
		return 0;
	}

	if (net->net_cpts == NULL) {
		LIBCFS_ALLOC(net->net_cpts, sizeof(*net->net_cpts) * ncpts);
		if (net->net_cpts == NULL)
			return -ENOMEM;
		memcpy(net->net_cpts, cpts, ncpts);
		net->net_ncpts = ncpts;
		return 0;
	}

	LIBCFS_ALLOC(added_cpts, sizeof(*added_cpts) * LNET_CPT_NUMBER);
	if (added_cpts == NULL)
		return -ENOMEM;

	for (i = 0; i < ncpts; i++) {
		if (!in_array(net->net_cpts, net->net_ncpts, cpts[i])) {
			added_cpts[j] = cpts[i];
			j++;
		}
	}

	/* append the new cpts if any to the list of cpts in the net */
	if (j > 0) {
		__u32 *array = NULL, *loc;
		__u32 total_entries = j + net->net_ncpts;

		LIBCFS_ALLOC(array, sizeof(*net->net_cpts) * total_entries);
		if (array == NULL) {
			rc = -ENOMEM;
			goto failed;
		}

		memcpy(array, net->net_cpts, net->net_ncpts);
		loc = array + net->net_ncpts;
		memcpy(loc, added_cpts, j);

		LIBCFS_FREE(net->net_cpts, sizeof(*net->net_cpts) *
			    net->net_ncpts);
		net->net_ncpts = total_entries;
		net->net_cpts = array;
	}

failed:
	LIBCFS_FREE(added_cpts, sizeof(*added_cpts) * LNET_CPT_NUMBER);

	return rc;
}

static void
lnet_net_remove_cpts(__u32 *cpts, __u32 ncpts, struct lnet_net *net)
{
	struct lnet_ni *ni;
	int rc;

	/*
	 * Operation Assumption:
	 *	This function is called after an NI has been removed from
	 *	its parent net.
	 *
	 * if we're removing an NI which exists on all CPTs then
	 * we have to check if any of the other NIs on this net also
	 * exists on all CPTs. If none, then we need to build our Net CPT
	 * list based on the remaining NIs.
	 *
	 * If the NI being removed exist on a subset of the CPTs then we
	 * alo rebuild the Net CPT list based on the remaining NIs, which
	 * should resutl in the expected Net CPT list.
	 */

	/*
	 * sometimes this function can be called due to some failure
	 * creating an NI, before any of the cpts are allocated, so check
	 * for that case and don't do anything
	 */
	if (ncpts == 0)
		return;

	if (ncpts == LNET_CPT_NUMBER) {
		/*
		 * first iteration through the NI list in the net to see
		 * if any of the NIs exist on all the CPTs. If one is
		 * found then our job is done.
		 */
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (ni->ni_ncpts == LNET_CPT_NUMBER)
				return;
		}
	}

	/*
	 * Rebuild the Net CPT list again, thereby only including only the
	 * CPTs which the remaining NIs are associated with.
	 */
	if (net->net_cpts != NULL) {
		LIBCFS_FREE(net->net_cpts,
			sizeof(*net->net_cpts) * net->net_ncpts);
		net->net_cpts = NULL;
	}

	list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
		rc = lnet_net_append_cpts(ni->ni_cpts, ni->ni_ncpts,
					  net);
		if (rc != 0) {
			CERROR("Out of Memory\n");
			/*
			 * do our best to keep on going. Delete
			 * the net cpts and set it to NULL. This
			 * way we can keep on going but less
			 * efficiently, since memory accesses might be
			 * accross CPT lines.
			 */
			if (net->net_cpts != NULL) {
				LIBCFS_FREE(net->net_cpts,
						sizeof(*net->net_cpts) *
						net->net_ncpts);
				net->net_cpts = NULL;
				net->net_ncpts = LNET_CPT_NUMBER;
			}
			return;
		}
	}
}

void
lnet_ni_free(struct lnet_ni *ni)
{
	int i;

	lnet_net_remove_cpts(ni->ni_cpts, ni->ni_ncpts, ni->ni_net);

	if (ni->ni_refs != NULL)
		cfs_percpt_free(ni->ni_refs);

	if (ni->ni_tx_queues != NULL)
		cfs_percpt_free(ni->ni_tx_queues);

	if (ni->ni_cpts != NULL)
		cfs_expr_list_values_free(ni->ni_cpts, ni->ni_ncpts);

	for (i = 0; i < LNET_NUM_INTERFACES &&
		    ni->ni_interfaces[i] != NULL; i++) {
		LIBCFS_FREE(ni->ni_interfaces[i],
			    strlen(ni->ni_interfaces[i]) + 1);
	}

	/* release reference to net namespace */
	if (ni->ni_net_ns != NULL)
		put_net(ni->ni_net_ns);

	LIBCFS_FREE(ni, sizeof(*ni));
}

void
lnet_net_free(struct lnet_net *net)
{
	struct list_head *tmp, *tmp2;
	struct lnet_ni *ni;

	LASSERT(list_empty(&net->net_ni_zombie));

	/*
	 * delete any nis that haven't been added yet. This could happen
	 * if there is a failure on net startup
	 */
	list_for_each_safe(tmp, tmp2, &net->net_ni_added) {
		ni = list_entry(tmp, struct lnet_ni, ni_netlist);
		list_del_init(&ni->ni_netlist);
		lnet_ni_free(ni);
	}

	/* delete any nis which have been started. */
	list_for_each_safe(tmp, tmp2, &net->net_ni_list) {
		ni = list_entry(tmp, struct lnet_ni, ni_netlist);
		list_del_init(&ni->ni_netlist);
		lnet_ni_free(ni);
	}

	if (net->net_cpts != NULL)
		LIBCFS_FREE(net->net_cpts,
			    sizeof(*net->net_cpts) * net->net_ncpts);

	LIBCFS_FREE(net, sizeof(*net));
}

struct lnet_net *
lnet_net_alloc(__u32 net_id, struct list_head *net_list)
{
	struct lnet_net		*net;

	if (!lnet_net_unique(net_id, net_list, NULL)) {
		CERROR("Duplicate net %s. Ignore\n",
		       libcfs_net2str(net_id));
		return NULL;
	}

	LIBCFS_ALLOC(net, sizeof(*net));
	if (net == NULL) {
		CERROR("Out of memory creating network %s\n",
		       libcfs_net2str(net_id));
		return NULL;
	}

	INIT_LIST_HEAD(&net->net_list);
	INIT_LIST_HEAD(&net->net_ni_list);
	INIT_LIST_HEAD(&net->net_ni_added);
	INIT_LIST_HEAD(&net->net_ni_zombie);

	net->net_id = net_id;
	net->net_state = LNET_NET_STATE_INIT;

	/* initialize global paramters to undefiend */
	net->net_tunables.lct_peer_timeout = -1;
	net->net_tunables.lct_max_tx_credits = -1;
	net->net_tunables.lct_peer_tx_credits = -1;
	net->net_tunables.lct_peer_rtr_credits = -1;

	if (net_list)
		list_add_tail(&net->net_list, net_list);

	return net;
}

static int
lnet_ni_add_interface(struct lnet_ni *ni, char *iface)
{
	int niface = 0;

	if (ni == NULL)
		return -ENOMEM;

	if (!lnet_ni_unique_ni(ni->ni_interfaces, iface))
		return -EINVAL;

	/* Allocate a separate piece of memory and copy
	 * into it the string, so we don't have
	 * a depencency on the tokens string.  This way we
	 * can free the tokens at the end of the function.
	 * The newly allocated ni_interfaces[] can be
	 * freed when freeing the NI */
	while (niface < LNET_NUM_INTERFACES &&
	       ni->ni_interfaces[niface] != NULL)
		niface++;

	if (niface >= LNET_NUM_INTERFACES) {
		LCONSOLE_ERROR_MSG(0x115, "Too many interfaces "
				   "for net %s\n",
				   libcfs_net2str(LNET_NIDNET(ni->ni_nid)));
		return -EINVAL;
	}

	LIBCFS_ALLOC(ni->ni_interfaces[niface],
		     strlen(iface) + 1);

	if (ni->ni_interfaces[niface] == NULL) {
		CERROR("Can't allocate net interface name\n");
		return -ENOMEM;
	}

	strncpy(ni->ni_interfaces[niface], iface,
		strlen(iface) + 1);

	return 0;
}

static struct lnet_ni *
lnet_ni_alloc_common(struct lnet_net *net, char *iface)
{
	struct lnet_tx_queue	*tq;
	struct lnet_ni		*ni;
	int			i;

	if (iface != NULL)
		/* make sure that this NI is unique in the net it's
		 * being added to */
		if (!lnet_ni_unique_net(&net->net_ni_added, iface))
			return NULL;

	LIBCFS_ALLOC(ni, sizeof(*ni));
	if (ni == NULL) {
		CERROR("Out of memory creating network interface %s%s\n",
		       libcfs_net2str(net->net_id),
		       (iface != NULL) ? iface : "");
		return NULL;
	}

	spin_lock_init(&ni->ni_lock);
	INIT_LIST_HEAD(&ni->ni_cptlist);
	INIT_LIST_HEAD(&ni->ni_netlist);
	ni->ni_refs = cfs_percpt_alloc(lnet_cpt_table(),
				       sizeof(*ni->ni_refs[0]));
	if (ni->ni_refs == NULL)
		goto failed;

	ni->ni_tx_queues = cfs_percpt_alloc(lnet_cpt_table(),
					    sizeof(*ni->ni_tx_queues[0]));
	if (ni->ni_tx_queues == NULL)
		goto failed;

	cfs_percpt_for_each(tq, i, ni->ni_tx_queues)
		INIT_LIST_HEAD(&tq->tq_delayed);

	ni->ni_net = net;
	/* LND will fill in the address part of the NID */
	ni->ni_nid = LNET_MKNID(net->net_id, 0);

	/* Store net namespace in which current ni is being created */
	if (current->nsproxy->net_ns != NULL)
		ni->ni_net_ns = get_net(current->nsproxy->net_ns);
	else
		ni->ni_net_ns = NULL;

	ni->ni_last_alive = cfs_time_current_sec();
	ni->ni_state = LNET_NI_STATE_INIT;
	list_add_tail(&ni->ni_netlist, &net->net_ni_added);

	/*
	 * if an interface name is provided then make sure to add in that
	 * interface name in NI
	 */
	if (iface)
		if (lnet_ni_add_interface(ni, iface) != 0)
			goto failed;

	return ni;
failed:
	lnet_ni_free(ni);
	return NULL;
}

/* allocate and add to the provided network */
struct lnet_ni *
lnet_ni_alloc(struct lnet_net *net, struct cfs_expr_list *el, char *iface)
{
	struct lnet_ni		*ni;
	int			rc;

	ni = lnet_ni_alloc_common(net, iface);
	if (!ni)
		return NULL;

	if (!el) {
		ni->ni_cpts  = NULL;
		ni->ni_ncpts = LNET_CPT_NUMBER;
	} else {
		rc = cfs_expr_list_values(el, LNET_CPT_NUMBER, &ni->ni_cpts);
		if (rc <= 0) {
			CERROR("Failed to set CPTs for NI %s(%s): %d\n",
			       libcfs_net2str(net->net_id),
			       (iface != NULL) ? iface : "", rc);
			goto failed;
		}

		LASSERT(rc <= LNET_CPT_NUMBER);
		if (rc == LNET_CPT_NUMBER) {
			LIBCFS_FREE(ni->ni_cpts, rc * sizeof(ni->ni_cpts[0]));
			ni->ni_cpts = NULL;
		}

		ni->ni_ncpts = rc;
	}

	rc = lnet_net_append_cpts(ni->ni_cpts, ni->ni_ncpts, net);
	if (rc != 0)
		goto failed;

	return ni;
failed:
	lnet_ni_free(ni);
	return NULL;
}

struct lnet_ni *
lnet_ni_alloc_w_cpt_array(struct lnet_net *net, __u32 *cpts, __u32 ncpts,
			  char *iface)
{
	struct lnet_ni		*ni;
	int			rc;

	ni = lnet_ni_alloc_common(net, iface);
	if (!ni)
		return NULL;

	if (ncpts == 0) {
		ni->ni_cpts  = NULL;
		ni->ni_ncpts = LNET_CPT_NUMBER;
	} else {
		size_t array_size = ncpts * sizeof(ni->ni_cpts[0]);
		LIBCFS_ALLOC(ni->ni_cpts, array_size);
		if (ni->ni_cpts == NULL)
			goto failed;
		memcpy(ni->ni_cpts, cpts, array_size);
		ni->ni_ncpts = ncpts;
	}

	rc = lnet_net_append_cpts(ni->ni_cpts, ni->ni_ncpts, net);
	if (rc != 0)
		goto failed;

	return ni;
failed:
	lnet_ni_free(ni);
	return NULL;
}

/*
 * Parse the networks string and create the matching set of NIs on the
 * nilist.
 */
int
lnet_parse_networks(struct list_head *netlist, char *networks,
		    bool use_tcp_bonding)
{
	struct cfs_expr_list *net_el = NULL;
	struct cfs_expr_list *ni_el = NULL;
	int		tokensize;
	char		*tokens;
	char		*str;
	struct lnet_net *net;
	struct lnet_ni	*ni = NULL;
	__u32		net_id;
	int		nnets = 0;

	if (networks == NULL) {
		CERROR("networks string is undefined\n");
		return -EINVAL;
	}

	if (strlen(networks) > LNET_SINGLE_TEXTBUF_NOB) {
		/* _WAY_ conservative */
		LCONSOLE_ERROR_MSG(0x112, "Can't parse networks: string too "
				   "long\n");
		return -EINVAL;
	}

	tokensize = strlen(networks) + 1;

	LIBCFS_ALLOC(tokens, tokensize);
	if (tokens == NULL) {
		CERROR("Can't allocate net tokens\n");
		return -ENOMEM;
	}

	memcpy(tokens, networks, tokensize);
	str = tokens;

	/*
	 * Main parser loop.
	 *
	 * NB we don't check interface conflicts here; it's the LNDs
	 * responsibility (if it cares at all)
	 */
	do {
		char *nistr;
		char *elstr;
		char *name;
		int rc;

		/*
		 * Parse a network string into its components.
		 *
		 * <name>{"("...")"}{"["<el>"]"}
		 */

		/* Network name (mandatory) */
		while (isspace(*str))
			*str++ = '\0';
		if (!*str)
			break;
		name = str;
		str += strcspn(str, SPACESTR ":()[],");
		while (isspace(*str))
			*str++ = '\0';

		/* Interface list (optional) */
		if (*str == '(') {
			*str++ = '\0';
			nistr = str;
			str += strcspn(str, ")");
			if (*str != ')') {
				str = nistr;
				goto failed_syntax;
			}
			do {
				*str++ = '\0';
			} while (isspace(*str));
		} else {
			nistr = NULL;
		}

		/* CPT expression (optional) */
		if (*str == '[') {
			elstr = str;
			str += strcspn(str, "]");
			if (*str != ']') {
				str = elstr;
				goto failed_syntax;
			}
			rc = cfs_expr_list_parse(elstr, str - elstr + 1,
						0, LNET_CPT_NUMBER - 1,
						&net_el);
			if (rc != 0) {
				str = elstr;
				goto failed_syntax;
			}
			*elstr = '\0';
			do {
				*str++ = '\0';
			} while (isspace(*str));
		}

		/* Bad delimiters */
		if (*str && (strchr(DELIMITERS, *str) != NULL))
			goto failed_syntax;

		/* go to the next net if it exits */
		str += strcspn(str, ",");
		if (*str == ',')
			*str++ = '\0';

		/*
		 * At this point the name is properly terminated.
		 */
		net_id = libcfs_str2net(name);
		if (net_id == LNET_NIDNET(LNET_NID_ANY)) {
			LCONSOLE_ERROR_MSG(0x113,
					"Unrecognised network type\n");
			str = name;
			goto failed_syntax;
		}

		if (LNET_NETTYP(net_id) == LOLND) {
			/* Loopback is implicit, and there can be only one. */
			if (net_el) {
				cfs_expr_list_free(net_el);
				net_el = NULL;
			}
			/* Should we error out instead? */
			continue;
		}

		/*
		 * All network paramaters are now known.
		 */
		nnets++;

		/* always allocate a net, since we will eventually add an
		 * interface to it, or we will fail, in which case we'll
		 * just delete it */
		net = lnet_net_alloc(net_id, netlist);
		if (IS_ERR_OR_NULL(net))
			goto failed;

		if (!nistr ||
		    (use_tcp_bonding && LNET_NETTYP(net_id) == SOCKLND)) {
			/*
			 * No interface list was specified, allocate a
			 * ni using the defaults.
			 */
			ni = lnet_ni_alloc(net, net_el, NULL);
			if (IS_ERR_OR_NULL(ni))
				goto failed;

			if (!nistr) {
				if (net_el) {
					cfs_expr_list_free(net_el);
					net_el = NULL;
				}
				continue;
			}
		}

		do {
			elstr = NULL;

			/* Interface name (mandatory) */
			while (isspace(*nistr))
				*nistr++ = '\0';
			name = nistr;
			nistr += strcspn(nistr, SPACESTR "[],");
			while (isspace(*nistr))
				*nistr++ = '\0';

			/* CPT expression (optional) */
			if (*nistr == '[') {
				elstr = nistr;
				nistr += strcspn(nistr, "]");
				if (*nistr != ']') {
					str = elstr;
					goto failed_syntax;
				}
				rc = cfs_expr_list_parse(elstr,
							nistr - elstr + 1,
							0, LNET_CPT_NUMBER - 1,
							&ni_el);
				if (rc != 0) {
					str = elstr;
					goto failed_syntax;
				}
				*elstr = '\0';
				do {
					*nistr++ = '\0';
				} while (isspace(*nistr));
			} else {
				ni_el = net_el;
			}

			/*
			 * End of single interface specificaton,
			 * advance to the start of the next one, if
			 * any.
			 */
			if (*nistr == ',') {
				do {
					*nistr++ = '\0';
				} while (isspace(*nistr));
				if (!*nistr) {
					str = nistr;
					goto failed_syntax;
				}
			} else if (*nistr) {
				str = nistr;
				goto failed_syntax;
			}

			/*
			 * At this point the name is properly terminated.
			 */
			if (!*name) {
				str = name;
				goto failed_syntax;
			}

			if (use_tcp_bonding &&
			    LNET_NETTYP(net->net_id) == SOCKLND) {
				rc = lnet_ni_add_interface(ni, name);
				if (rc != 0)
					goto failed;
			} else {
				ni = lnet_ni_alloc(net, ni_el, name);
				if (IS_ERR_OR_NULL(ni))
					goto failed;
			}

			if (ni_el) {
				if (ni_el != net_el) {
					cfs_expr_list_free(ni_el);
					ni_el = NULL;
				}
			}
		} while (*nistr);

		if (net_el) {
			cfs_expr_list_free(net_el);
			net_el = NULL;
		}
	} while (*str);

	LIBCFS_FREE(tokens, tokensize);
	return nnets;

 failed_syntax:
	lnet_syntax("networks", networks, (int)(str - tokens), strlen(str));
 failed:
	/* free the net list and all the nis on each net */
	while (!list_empty(netlist)) {
		net = list_entry(netlist->next, struct lnet_net, net_list);

		list_del_init(&net->net_list);
		lnet_net_free(net);
	}

	if (ni_el && ni_el != net_el)
		cfs_expr_list_free(ni_el);
	if (net_el)
		cfs_expr_list_free(net_el);

	LIBCFS_FREE(tokens, tokensize);

	return -EINVAL;
}

static struct lnet_text_buf *lnet_new_text_buf(int str_len)
{
	struct lnet_text_buf *ltb;
	int nob;

	/* NB allocate space for the terminating 0 */
	nob = offsetof(struct lnet_text_buf, ltb_text[str_len + 1]);
	if (nob > LNET_SINGLE_TEXTBUF_NOB) {
		/* _way_ conservative for "route net gateway..." */
		CERROR("text buffer too big\n");
		return NULL;
	}

	if (lnet_tbnob + nob > LNET_MAX_TEXTBUF_NOB) {
		CERROR("Too many text buffers\n");
		return NULL;
	}

	LIBCFS_ALLOC(ltb, nob);
	if (ltb == NULL)
		return NULL;

	ltb->ltb_size = nob;
	ltb->ltb_text[0] = 0;
	lnet_tbnob += nob;
	return ltb;
}

static void
lnet_free_text_buf(struct lnet_text_buf *ltb)
{
	lnet_tbnob -= ltb->ltb_size;
	LIBCFS_FREE(ltb, ltb->ltb_size);
}

static void
lnet_free_text_bufs(struct list_head *tbs)
{
	struct lnet_text_buf  *ltb;

	while (!list_empty(tbs)) {
		ltb = list_entry(tbs->next, struct lnet_text_buf, ltb_list);

		list_del(&ltb->ltb_list);
		lnet_free_text_buf(ltb);
	}
}

void
lnet_print_text_bufs(struct list_head *tbs)
{
	struct list_head *tmp;
	struct lnet_text_buf  *ltb;

	list_for_each(tmp, tbs) {
		ltb = list_entry(tmp, struct lnet_text_buf, ltb_list);

		CDEBUG(D_WARNING, "%s\n", ltb->ltb_text);
	}

	CDEBUG(D_WARNING, "%d allocated\n", lnet_tbnob);
}

static int
lnet_str2tbs_sep(struct list_head *tbs, char *str)
{
	struct list_head  pending;
	char		 *sep;
	int		  nob;
	int		  i;
	struct lnet_text_buf  *ltb;

	INIT_LIST_HEAD(&pending);

	/* Split 'str' into separate commands */
	for (;;) {
		/* skip leading whitespace */
		while (isspace(*str))
			str++;

		/* scan for separator or comment */
		for (sep = str; *sep != 0; sep++)
			if (lnet_issep(*sep) || *sep == '#')
				break;

		nob = (int)(sep - str);
		if (nob > 0) {
			ltb = lnet_new_text_buf(nob);
			if (ltb == NULL) {
				lnet_free_text_bufs(&pending);
				return -ENOMEM;
			}

			for (i = 0; i < nob; i++)
				if (isspace(str[i]))
					ltb->ltb_text[i] = ' ';
				else
					ltb->ltb_text[i] = str[i];

			ltb->ltb_text[nob] = 0;

			list_add_tail(&ltb->ltb_list, &pending);
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

static int
lnet_expand1tb(struct list_head *list,
	       char *str, char *sep1, char *sep2,
	       char *item, int itemlen)
{
	int		 len1 = (int)(sep1 - str);
	int		 len2 = strlen(sep2 + 1);
	struct lnet_text_buf *ltb;

	LASSERT (*sep1 == '[');
	LASSERT (*sep2 == ']');

	ltb = lnet_new_text_buf(len1 + itemlen + len2);
	if (ltb == NULL)
		return -ENOMEM;

	memcpy(ltb->ltb_text, str, len1);
	memcpy(&ltb->ltb_text[len1], item, itemlen);
	memcpy(&ltb->ltb_text[len1+itemlen], sep2 + 1, len2);
	ltb->ltb_text[len1 + itemlen + len2] = 0;

	list_add_tail(&ltb->ltb_list, list);
	return 0;
}

static int
lnet_str2tbs_expand(struct list_head *tbs, char *str)
{
	char		  num[16];
	struct list_head  pending;
	char		 *sep;
	char		 *sep2;
	char		 *parsed;
	char		 *enditem;
	int		  lo;
	int		  hi;
	int		  stride;
	int		  i;
	int		  nob;
	int		  scanned;

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
						   parsed, (int)(enditem - parsed)) != 0)
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
	return -EINVAL;
}

static int
lnet_parse_hops (char *str, unsigned int *hops)
{
	int	len = strlen(str);
	int	nob = len;

	return (sscanf(str, "%u%n", hops, &nob) >= 1 &&
		nob == len &&
		*hops > 0 && *hops < 256);
}

#define LNET_PRIORITY_SEPARATOR (':')

static int
lnet_parse_priority(char *str, unsigned int *priority, char **token)
{
	int   nob;
	char *sep;
	int   len;

	sep = strchr(str, LNET_PRIORITY_SEPARATOR);
	if (sep == NULL) {
		*priority = 0;
		return 0;
	}
	len = strlen(sep + 1);

	if ((sscanf((sep+1), "%u%n", priority, &nob) < 1) || (len != nob)) {
		/* Update the caller's token pointer so it treats the found
		   priority as the token to report in the error message. */
		*token += sep - str + 1;
		return -EINVAL;
	}

	CDEBUG(D_NET, "gateway %s, priority %d, nob %d\n", str, *priority, nob);

	/*
	 * Change priority separator to \0 to be able to parse NID
	 */
	*sep = '\0';
	return 0;
}

static int
lnet_parse_route (char *str, int *im_a_router)
{
	/* static scratch buffer OK (single threaded) */
	static char	  cmd[LNET_SINGLE_TEXTBUF_NOB];

	struct list_head  nets;
	struct list_head  gateways;
	struct list_head *tmp1;
	struct list_head *tmp2;
	__u32		  net;
	lnet_nid_t	  nid;
	struct lnet_text_buf  *ltb;
	int		  rc;
	char		 *sep;
	char		 *token = str;
	int		  ntokens = 0;
	int		  myrc = -1;
	__u32		  hops;
	int		  got_hops = 0;
	unsigned int	  priority = 0;

	INIT_LIST_HEAD(&gateways);
	INIT_LIST_HEAD(&nets);

	/* save a copy of the string for error messages */
	strncpy(cmd, str, sizeof(cmd));
	cmd[sizeof(cmd) - 1] = '\0';

	sep = str;
	for (;;) {
		/* scan for token start */
		while (isspace(*sep))
			sep++;
		if (*sep == 0) {
			if (ntokens < (got_hops ? 3 : 2))
				goto token_error;
			break;
		}

		ntokens++;
		token = sep++;

		/* scan for token end */
		while (*sep != 0 && !isspace(*sep))
			sep++;
		if (*sep != 0)
			*sep++ = 0;

		if (ntokens == 1) {
			tmp2 = &nets;		/* expanding nets */
		} else if (ntokens == 2 &&
			   lnet_parse_hops(token, &hops)) {
			got_hops = 1;		/* got a hop count */
			continue;
		} else {
			tmp2 = &gateways;	/* expanding gateways */
		}

		ltb = lnet_new_text_buf(strlen(token));
		if (ltb == NULL)
			goto out;

		strcpy(ltb->ltb_text, token);
		tmp1 = &ltb->ltb_list;
		list_add_tail(tmp1, tmp2);

		while (tmp1 != tmp2) {
			ltb = list_entry(tmp1, struct lnet_text_buf, ltb_list);

			rc = lnet_str2tbs_expand(tmp1->next, ltb->ltb_text);
			if (rc < 0)
				goto token_error;

			tmp1 = tmp1->next;

			if (rc > 0) {		/* expanded! */
				list_del(&ltb->ltb_list);
				lnet_free_text_buf(ltb);
				continue;
			}

			if (ntokens == 1) {
				net = libcfs_str2net(ltb->ltb_text);
				if (net == LNET_NIDNET(LNET_NID_ANY) ||
				    LNET_NETTYP(net) == LOLND)
					goto token_error;
			} else {
				rc = lnet_parse_priority(ltb->ltb_text,
							 &priority, &token);
				if (rc < 0)
					goto token_error;

				nid = libcfs_str2nid(ltb->ltb_text);
				if (nid == LNET_NID_ANY ||
				    LNET_NETTYP(LNET_NIDNET(nid)) == LOLND)
					goto token_error;
			}
		}
	}

	/* if there are no hops set then we want to flag this value as
	 * unset since hops is an optional parameter */
	if (!got_hops)
		hops = LNET_UNDEFINED_HOPS;

	LASSERT(!list_empty(&nets));
	LASSERT(!list_empty(&gateways));

	list_for_each(tmp1, &nets) {
		ltb = list_entry(tmp1, struct lnet_text_buf, ltb_list);
		net = libcfs_str2net(ltb->ltb_text);
		LASSERT (net != LNET_NIDNET(LNET_NID_ANY));

		list_for_each(tmp2, &gateways) {
			ltb = list_entry(tmp2, struct lnet_text_buf, ltb_list);
			nid = libcfs_str2nid(ltb->ltb_text);
			LASSERT(nid != LNET_NID_ANY);

			if (lnet_islocalnid(nid)) {
				*im_a_router = 1;
				continue;
			}

			rc = lnet_add_route(net, hops, nid, priority);
			if (rc != 0 && rc != -EEXIST && rc != -EHOSTUNREACH) {
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
	lnet_syntax("routes", cmd, (int)(token - str), strlen(token));
out:
	lnet_free_text_bufs(&nets);
	lnet_free_text_bufs(&gateways);
	return myrc;
}

static int
lnet_parse_route_tbs(struct list_head *tbs, int *im_a_router)
{
	struct lnet_text_buf   *ltb;

	while (!list_empty(tbs)) {
		ltb = list_entry(tbs->next, struct lnet_text_buf, ltb_list);

		if (lnet_parse_route(ltb->ltb_text, im_a_router) < 0) {
			lnet_free_text_bufs(tbs);
			return -EINVAL;
		}

		list_del(&ltb->ltb_list);
		lnet_free_text_buf(ltb);
	}

	return 0;
}

int
lnet_parse_routes (char *routes, int *im_a_router)
{
	struct list_head tbs;
	int		 rc = 0;

	*im_a_router = 0;

	INIT_LIST_HEAD(&tbs);

	if (lnet_str2tbs_sep(&tbs, routes) < 0) {
		CERROR("Error parsing routes\n");
		rc = -EINVAL;
	} else {
		rc = lnet_parse_route_tbs(&tbs, im_a_router);
	}

	LASSERT (lnet_tbnob == 0);
	return rc;
}

static int
lnet_match_network_token(char *token, int len, __u32 *ipaddrs, int nip)
{
	struct list_head list = LIST_HEAD_INIT(list);
	int		rc;
	int		i;

	rc = cfs_ip_addr_parse(token, len, &list);
	if (rc != 0)
		return rc;

	for (rc = i = 0; !rc && i < nip; i++)
		rc = cfs_ip_addr_match(ipaddrs[i], &list);

	cfs_expr_list_free_list(&list);

	return rc;
}

static int
lnet_match_network_tokens(char *net_entry, __u32 *ipaddrs, int nip)
{
	static char tokens[LNET_SINGLE_TEXTBUF_NOB];

	int   matched = 0;
	int   ntokens = 0;
	int   len;
	char *net = NULL;
	char *sep;
	char *token;
	int   rc;

	LASSERT(strlen(net_entry) < sizeof(tokens));

	/* work on a copy of the string */
	strcpy(tokens, net_entry);
	sep = tokens;
	for (;;) {
		/* scan for token start */
		while (isspace(*sep))
			sep++;
		if (*sep == 0)
			break;

		token = sep++;

		/* scan for token end */
		while (*sep != 0 && !isspace(*sep))
			sep++;
		if (*sep != 0)
			*sep++ = 0;

		if (ntokens++ == 0) {
			net = token;
			continue;
		}

		len = strlen(token);

		rc = lnet_match_network_token(token, len, ipaddrs, nip);
		if (rc < 0) {
			lnet_syntax("ip2nets", net_entry,
				    (int)(token - tokens), len);
			return rc;
		}

		matched |= (rc != 0);
	}

	if (!matched)
		return 0;

	strcpy(net_entry, net);			/* replace with matched net */
	return 1;
}

static __u32
lnet_netspec2net(char *netspec)
{
	char   *bracket = strchr(netspec, '(');
	__u32	net;

	if (bracket != NULL)
		*bracket = 0;

	net = libcfs_str2net(netspec);

	if (bracket != NULL)
		*bracket = '(';

	return net;
}

static int
lnet_splitnets(char *source, struct list_head *nets)
{
	int		  offset = 0;
	int		  offset2;
	int		  len;
	struct lnet_text_buf  *tb;
	struct lnet_text_buf  *tb2;
	struct list_head *t;
	char		 *sep;
	char		 *bracket;
	__u32		  net;

	LASSERT(!list_empty(nets));
	LASSERT(nets->next == nets->prev);	/* single entry */

	tb = list_entry(nets->next, struct lnet_text_buf, ltb_list);

	for (;;) {
		sep = strchr(tb->ltb_text, ',');
		bracket = strchr(tb->ltb_text, '(');

		if (sep != NULL &&
		    bracket != NULL &&
		    bracket < sep) {
			/* netspec lists interfaces... */

			offset2 = offset + (int)(bracket - tb->ltb_text);
			len = strlen(bracket);

			bracket = strchr(bracket + 1, ')');

			if (bracket == NULL ||
			    !(bracket[1] == ',' || bracket[1] == 0)) {
				lnet_syntax("ip2nets", source, offset2, len);
				return -EINVAL;
			}

			sep = (bracket[1] == 0) ? NULL : bracket + 1;
		}

		if (sep != NULL)
			*sep++ = 0;

		net = lnet_netspec2net(tb->ltb_text);
		if (net == LNET_NIDNET(LNET_NID_ANY)) {
			lnet_syntax("ip2nets", source, offset,
				    strlen(tb->ltb_text));
			return -EINVAL;
		}

		list_for_each(t, nets) {
			tb2 = list_entry(t, struct lnet_text_buf, ltb_list);

			if (tb2 == tb)
				continue;

			if (net == lnet_netspec2net(tb2->ltb_text)) {
				/* duplicate network */
				lnet_syntax("ip2nets", source, offset,
					    strlen(tb->ltb_text));
				return -EINVAL;
			}
		}

		if (sep == NULL)
			return 0;

		offset += (int)(sep - tb->ltb_text);
		len = strlen(sep);
		tb2 = lnet_new_text_buf(len);
		if (tb2 == NULL)
			return -ENOMEM;

		strncpy(tb2->ltb_text, sep, len);
		tb2->ltb_text[len] = '\0';
		list_add_tail(&tb2->ltb_list, nets);

		tb = tb2;
	}
}

static int
lnet_match_networks (char **networksp, char *ip2nets, __u32 *ipaddrs, int nip)
{
	static char	  networks[LNET_SINGLE_TEXTBUF_NOB];
	static char	  source[LNET_SINGLE_TEXTBUF_NOB];

	struct list_head  raw_entries;
	struct list_head  matched_nets;
	struct list_head  current_nets;
	struct list_head *t;
	struct list_head *t2;
	struct lnet_text_buf  *tb;
	struct lnet_text_buf  *tb2;
	__u32		  net1;
	__u32		  net2;
	int		  len;
	int		  count;
	int		  dup;
	int		  rc;

	INIT_LIST_HEAD(&raw_entries);
	if (lnet_str2tbs_sep(&raw_entries, ip2nets) < 0) {
		CERROR("Error parsing ip2nets\n");
		LASSERT(lnet_tbnob == 0);
		return -EINVAL;
	}

	INIT_LIST_HEAD(&matched_nets);
	INIT_LIST_HEAD(&current_nets);
	networks[0] = 0;
	count = 0;
	len = 0;
	rc = 0;

	while (!list_empty(&raw_entries)) {
		tb = list_entry(raw_entries.next, struct lnet_text_buf,
				ltb_list);

		strncpy(source, tb->ltb_text, sizeof(source));
		source[sizeof(source) - 1] = '\0';

		/* replace ltb_text with the network(s) add on match */
		rc = lnet_match_network_tokens(tb->ltb_text, ipaddrs, nip);
		if (rc < 0)
			break;

		list_del(&tb->ltb_list);

		if (rc == 0) {			/* no match */
			lnet_free_text_buf(tb);
			continue;
		}

		/* split into separate networks */
		INIT_LIST_HEAD(&current_nets);
		list_add(&tb->ltb_list, &current_nets);
		rc = lnet_splitnets(source, &current_nets);
		if (rc < 0)
			break;

		dup = 0;
		list_for_each(t, &current_nets) {
			tb = list_entry(t, struct lnet_text_buf, ltb_list);
			net1 = lnet_netspec2net(tb->ltb_text);
			LASSERT(net1 != LNET_NIDNET(LNET_NID_ANY));

			list_for_each(t2, &matched_nets) {
				tb2 = list_entry(t2, struct lnet_text_buf,
						 ltb_list);
				net2 = lnet_netspec2net(tb2->ltb_text);
				LASSERT(net2 != LNET_NIDNET(LNET_NID_ANY));

				if (net1 == net2) {
					dup = 1;
					break;
				}
			}

			if (dup)
				break;
		}

		if (dup) {
			lnet_free_text_bufs(&current_nets);
			continue;
		}

		list_for_each_safe(t, t2, &current_nets) {
			tb = list_entry(t, struct lnet_text_buf, ltb_list);

			list_del(&tb->ltb_list);
			list_add_tail(&tb->ltb_list, &matched_nets);

			len += snprintf(networks + len, sizeof(networks) - len,
					"%s%s", (len == 0) ? "" : ",",
					tb->ltb_text);

			if (len >= sizeof(networks)) {
				CERROR("Too many matched networks\n");
				rc = -E2BIG;
				goto out;
			}
		}

		count++;
	}

 out:
	lnet_free_text_bufs(&raw_entries);
	lnet_free_text_bufs(&matched_nets);
	lnet_free_text_bufs(&current_nets);
	LASSERT(lnet_tbnob == 0);

	if (rc < 0)
		return rc;

	*networksp = networks;
	return count;
}

static void
lnet_ipaddr_free_enumeration(__u32 *ipaddrs, int nip)
{
	LIBCFS_FREE(ipaddrs, nip * sizeof(*ipaddrs));
}

static int
lnet_ipaddr_enumerate (__u32 **ipaddrsp)
{
	int	   up;
	__u32	   netmask;
	__u32	  *ipaddrs;
	__u32	  *ipaddrs2;
	int	   nip;
	char	 **ifnames;
	int	   nif = lnet_ipif_enumerate(&ifnames);
	int	   i;
	int	   rc;

	if (nif <= 0)
		return nif;

	LIBCFS_ALLOC(ipaddrs, nif * sizeof(*ipaddrs));
	if (ipaddrs == NULL) {
		CERROR("Can't allocate ipaddrs[%d]\n", nif);
		lnet_ipif_free_enumeration(ifnames, nif);
		return -ENOMEM;
	}

	for (i = nip = 0; i < nif; i++) {
		if (!strcmp(ifnames[i], "lo"))
			continue;

		rc = lnet_ipif_query(ifnames[i], &up,
				       &ipaddrs[nip], &netmask);
		if (rc != 0) {
			CWARN("Can't query interface %s: %d\n",
			      ifnames[i], rc);
			continue;
		}

		if (!up) {
			CWARN("Ignoring interface %s: it's down\n",
			      ifnames[i]);
			continue;
		}

		nip++;
	}

	lnet_ipif_free_enumeration(ifnames, nif);

	if (nip == nif) {
		*ipaddrsp = ipaddrs;
	} else {
		if (nip > 0) {
			LIBCFS_ALLOC(ipaddrs2, nip * sizeof(*ipaddrs2));
			if (ipaddrs2 == NULL) {
				CERROR("Can't allocate ipaddrs[%d]\n", nip);
				nip = -ENOMEM;
			} else {
				memcpy(ipaddrs2, ipaddrs,
					nip * sizeof(*ipaddrs));
				*ipaddrsp = ipaddrs2;
				rc = nip;
			}
		}
		lnet_ipaddr_free_enumeration(ipaddrs, nif);
	}
	return nip;
}

int
lnet_parse_ip2nets (char **networksp, char *ip2nets)
{
	__u32	  *ipaddrs = NULL;
	int	   nip = lnet_ipaddr_enumerate(&ipaddrs);
	int	   rc;

	if (nip < 0) {
		LCONSOLE_ERROR_MSG(0x117, "Error %d enumerating local IP "
				   "interfaces for ip2nets to match\n", nip);
		return nip;
	}

	if (nip == 0) {
		LCONSOLE_ERROR_MSG(0x118, "No local IP interfaces "
				   "for ip2nets to match\n");
		return -ENOENT;
	}

	rc = lnet_match_networks(networksp, ip2nets, ipaddrs, nip);
	lnet_ipaddr_free_enumeration(ipaddrs, nip);

	if (rc < 0) {
		LCONSOLE_ERROR_MSG(0x119, "Error %d parsing ip2nets\n", rc);
		return rc;
	}

	if (rc == 0) {
		LCONSOLE_ERROR_MSG(0x11a, "ip2nets does not match "
				   "any local IP interfaces\n");
		return -ENOENT;
	}

	return 0;
}
