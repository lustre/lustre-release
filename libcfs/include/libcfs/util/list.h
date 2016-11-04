/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */

#ifndef __LIBCFS_UTIL_LIST_H__
#define __LIBCFS_UTIL_LIST_H__

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

#define prefetch(a) ((void)a)

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/**
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head * new,
				  struct list_head * prev,
				  struct list_head * next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * Insert an entry at the start of a list.
 * \param new  new entry to be inserted
 * \param head list to add it to
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *new,
				struct list_head *head)
{
	__list_add(new, head, head->next);
}

/**
 * Insert an entry at the end of a list.
 * \param new  new entry to be inserted
 * \param head list to add it to
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *new,
				     struct list_head *head)
{
	__list_add(new, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head *prev,
				  struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * Remove an entry from the list it is currently in.
 * \param entry the entry to remove
 * Note: list_empty(entry) does not return true after this, the entry is in an
 * undefined state.
 */
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

/**
 * Remove an entry from the list it is currently in and reinitialize it.
 * \param entry the entry to remove.
 */
static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

/**
 * Remove an entry from the list it is currently in and insert it at the start
 * of another list.
 * \param list the entry to move
 * \param head the list to move it to
 */
static inline void list_move(struct list_head *list,
				 struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add(list, head);
}

/**
 * Remove an entry from the list it is currently in and insert it at the end of
 * another list.
 * \param list the entry to move
 * \param head the list to move it to
 */
static inline void list_move_tail(struct list_head *list,
				      struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add_tail(list, head);
}

/**
 * Test whether a list is empty
 * \param head the list to test.
 */
static inline int list_empty(struct list_head *head)
{
	return head->next == head;
}

/**
 * Test whether a list is empty and not being modified
 * \param head the list to test
 *
 * Tests whether a list is empty _and_ checks that no other CPU might be
 * in the process of modifying either member (next or prev)
 *
 * NOTE: using list_empty_careful() without synchronization
 * can only be safe if the only activity that can happen
 * to the list entry is list_del_init(). Eg. it cannot be used
 * if another CPU could re-list_add() it.
 */
static inline int list_empty_careful(const struct list_head *head)
{
	struct list_head *next = head->next;
	return (next == head) && (next == head->prev);
}

static inline void __list_splice(struct list_head *list,
				     struct list_head *head)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;
	struct list_head *at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}

/**
 * Join two lists
 * \param list the new list to add.
 * \param head the place to add it in the first list.
 *
 * The contents of \a list are added at the start of \a head.  \a list is in an
 * undefined state on return.
 */
static inline void list_splice(struct list_head *list,
				   struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head);
}

static inline void list_splice_tail(struct list_head *list, struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head->prev);
}

/**
 * Join two lists and reinitialise the emptied list.
 * \param list the new list to add.
 * \param head the place to add it in the first list.
 *
 * The contents of \a list are added at the start of \a head.  \a list is empty
 * on return.
 */
static inline void list_splice_init(struct list_head *list,
					struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head);
		INIT_LIST_HEAD(list);
	}
}

/**
 * Get the container of a list
 * \param ptr	 the embedded list.
 * \param type	 the type of the struct this is embedded in.
 * \param member the member name of the list within the struct.
 */
#define list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(char *)(&((type *)0)->member)))

/**
 * Iterate over a list
 * \param pos	the iterator
 * \param head	the list to iterate over
 *
 * Behaviour is undefined if \a pos is removed from the list in the body of the
 * loop.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next, prefetch(pos->next); pos != (head); \
		pos = pos->next, prefetch(pos->next))

/**
 * Iterate over a list safely
 * \param pos	the iterator
 * \param n     temporary storage
 * \param head	the list to iterate over
 *
 * This is safe to use if \a pos could be removed from the list in the body of
 * the loop.
 */
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * Iterate over a list continuing after existing point
 * \param pos    the type * to use as a loop counter
 * \param head   the list head
 * \param member the name of the list_struct within the struct
 */
#define list_for_each_entry_continue(pos, head, member)                 \
	for (pos = list_entry(pos->member.next, typeof(*pos), member);  \
	     prefetch(pos->member.next), &pos->member != (head);        \
	     pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * \defgroup hlist Hash List
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is too
 * wasteful.  You lose the ability to access the tail in O(1).
 * @{
 */

struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct hlist_head {
	struct hlist_node *first;
};

/* @} */

/*
 * "NULL" might not be defined at this point
 */
#ifdef NULL
#define NULL_P NULL
#else
#define NULL_P ((void *)0)
#endif

/**
 * \addtogroup hlist
 * @{
 */

#define HLIST_HEAD_INIT { NULL_P }
#define HLIST_HEAD(name) struct hlist_head name = { NULL_P }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL_P)
#define INIT_HLIST_NODE(ptr) ((ptr)->next = NULL_P, (ptr)->pprev = NULL_P)

static inline int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
}

static inline void hlist_del_init(struct hlist_node *n)
{
	if (n->pprev)  {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

static inline void hlist_add_head(struct hlist_node *n,
				      struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

/* next must be != NULL */
static inline void hlist_add_before(struct hlist_node *n,
					struct hlist_node *next)
{
	n->pprev = next->pprev;
	n->next = next;
	next->pprev = &n->next;
	*(n->pprev) = n;
}

static inline void hlist_add_after(struct hlist_node *n,
				       struct hlist_node *next)
{
	next->next = n->next;
	n->next = next;
	next->pprev = &n->next;

	if(next->next)
		next->next->pprev  = &next->next;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos && (prefetch(pos->next), 1); \
	     pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && (n = pos->next, 1); \
	     pos = n)

/**
 * Iterate over an hlist of given type
 * \param tpos	 the type * to use as a loop counter.
 * \param pos	 the &struct hlist_node to use as a loop counter.
 * \param head	 the head for your list.
 * \param member the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(tpos, pos, head, member)                    \
	for (pos = (head)->first;                                            \
	     pos && ({ prefetch(pos->next); 1;}) &&                          \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * Iterate over an hlist continuing after existing point
 * \param tpos	 the type * to use as a loop counter.
 * \param pos	 the &struct hlist_node to use as a loop counter.
 * \param member the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue(tpos, pos, member)                 \
	for (pos = (pos)->next;                                              \
	     pos && ({ prefetch(pos->next); 1;}) &&                          \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * Iterate over an hlist continuing from an existing point
 * \param tpos	 the type * to use as a loop counter.
 * \param pos	 the &struct hlist_node to use as a loop counter.
 * \param member the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(tpos, pos, member)			 \
	for (; pos && ({ prefetch(pos->next); 1;}) &&                        \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * Iterate over an hlist of given type safe against removal of list entry
 * \param tpos	 the type * to use as a loop counter.
 * \param pos	 the &struct hlist_node to use as a loop counter.
 * \param n	 another &struct hlist_node to use as temporary storage
 * \param head	 the head for your list.
 * \param member the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_safe(tpos, pos, n, head, member)            \
	for (pos = (head)->first;                                            \
	     pos && ({ n = pos->next; 1; }) &&                               \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)

/* @} */

/**
 * Iterate over a list in reverse order
 * \param pos	the &struct list_head to use as a loop counter.
 * \param head	the head for your list.
 */
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev, prefetch(pos->prev); pos != (head);     \
		pos = pos->prev, prefetch(pos->prev))

/**
 * Iterate over a list of given type
 * \param pos        the type * to use as a loop counter.
 * \param head       the head for your list.
 * \param member     the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)                          \
	for (pos = list_entry((head)->next, typeof(*pos), member),      \
		     prefetch(pos->member.next);                            \
	     &pos->member != (head);                                        \
	     pos = list_entry(pos->member.next, typeof(*pos), member),  \
	     prefetch(pos->member.next))

/**
 * Iterate backwards over a list of given type.
 * \param pos        the type * to use as a loop counter.
 * \param head       the head for your list.
 * \param member     the name of the list_struct within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)                  \
	for (pos = list_entry((head)->prev, typeof(*pos), member);      \
	     prefetch(pos->member.prev), &pos->member != (head);            \
	     pos = list_entry(pos->member.prev, typeof(*pos), member))

/**
 * Iterate over a list of given type safe against removal of list entry
 * \param pos        the type * to use as a loop counter.
 * \param n          another type * to use as temporary storage
 * \param head       the head for your list.
 * \param member     the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)                   \
	for (pos = list_entry((head)->next, typeof(*pos), member),       \
		n = list_entry(pos->member.next, typeof(*pos), member);  \
	     &pos->member != (head);                                         \
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

/**
 * Iterate backwards over a list of given type safely against removal of entry
 * \param pos        the type * to use as a loop counter.
 * \param n          another type * to use as temporary storage
 * \param head       the head for your list.
 * \param member     the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_entry((head)->prev, typeof(*pos), member),	\
		n = list_entry(pos->member.prev, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.prev, typeof(*n), member))

#endif /* __LIBCFS_UTIL_LIST_H__ */
