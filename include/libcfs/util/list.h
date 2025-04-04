/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_UTIL_LIST_H__
#define __LIBCFS_UTIL_LIST_H__

/**
 * DOC: Simple doubly linked list implementation.
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

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head *new, struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * list_add() - Insert an entry at the start of a list.
 * @new:  new entry to be inserted
 * @head: list to add it to
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 *
 * Return:
 * * %void - Does not return any value
 */
static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

/**
 * list_add_tail() - Insert an entry at the end of a list.
 * @new:  new entry to be inserted
 * @head: list to add it to
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 *
 * Return:
 * * %void - Does not return any value
 */
static inline void list_add_tail(struct list_head *new, struct list_head *head)
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
static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * list_del() - Remove an entry from the list it is currently in.
 * @entry: the entry to remove
 *
 * Note: list_empty(entry) does not return true after this,
 * the entry is in an undefined state.
 *
 * Return:
 * * %void - Does not return any value
 */
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

/**
 * list_del_init() - Remove entry from the list and reinitialize it.
 * @entry: the entry to remove.
 *
 * Remove an entry from the list it is currently in and reinitialize it.
 *
 * Return:
 * * %void - Does not return any value
 */
static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

/**
 * list_move() - Remove entry and insert it at the start of another list
 * @list: the entry to move
 * @head: the list to move it to
 *
 * Remove an entry from the list it is currently in and insert
 * it at the start
 *
 * Return:
 * * %void - Does not return any value
 */
static inline void list_move(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add(list, head);
}

/**
 * list_move_tail() - Remove entry and insert it at the end of another list.
 * @list: the entry to move
 * @head: the list to move it to
 *
 * Remove an entry from the list it is currently in and insert
 * it at the end of
 *
 * Return:
 * * %void - Does not return any value
 */
static inline void list_move_tail(struct list_head *list,
				  struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add_tail(list, head);
}

/**
 * list_empty() - Test whether a list is empty
 * @head: the list to test.
 *
 * Return:
 * * %void - Does not return any value
 */
static inline int list_empty(struct list_head *head)
{
	return head->next == head;
}

/**
 * list_empty_careful() - Test whether a list is empty and not being modified
 * @head: the list to test
 *
 * Tests whether a list is empty _and_ checks that no other CPU might be
 * in the process of modifying either member (next or prev)
 *
 * NOTE: using list_empty_careful() without synchronization
 * can only be safe if the only activity that can happen
 * to the list entry is list_del_init(). Eg. it cannot be used
 * if another CPU could re-list_add() it.
 *
 * Return:
 * * %void - Does not return any value
 */
static inline int list_empty_careful(const struct list_head *head)
{
	struct list_head *next = head->next;

	return (next == head) && (next == head->prev);
}

static inline void __list_splice(struct list_head *list, struct list_head *head)
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
 * list_splice() - Join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The contents of @list are added at the start of @head.
 * @list is in an undefined state on return.
 *
 * Return:
 * * %void - Does not return any value
 */
static inline void list_splice(struct list_head *list, struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head);
}

/**
 * list_splice_tail() - Join two lists at the tail
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The contents of @list are added at the tail
 * @list is in an undefined state on return.
 *
 * Return:
 * * %void - Does not return any value
 */
static inline void list_splice_tail(struct list_head *list,
				    struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head->prev);
}

/**
 * list_splice_init() - Join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The contents of @list are added at the start of @head.
 * @list is empty on return.
 *
 * Return:
 * * %void - Does not return any value
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
 * define list_entry - Get the container of a list
 * @ptr: the embedded list.
 * @type: the type of the struct this is embedded in.
 * @member: the member name of the list within the struct.
 */
#define list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(char *)(&((type *)0)->member)))

/**
 * define list_first_entry - get the first element from a list
 * @ptr: the list head to take the element from.
 * @type: the type of the struct this is embedded in.
 * @member: the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/**
 * define list_last_entry - get the last element from a list
 * @ptr: the list head to take the element from.
 * @type: the type of the struct this is embedded in.
 * @member: the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

/**
 * define list_for_each - Iterate over a list
 * @pos: the iterator
 * @head: the list to iterate over
 *
 * Behaviour is undefined if @pos is removed from the list in the body of the
 * loop.
 */
#define list_for_each(pos, head)					\
	for (pos = (head)->next, prefetch(pos->next); pos != (head);	\
		pos = pos->next, prefetch(pos->next))

/**
 * define list_for_each_safe - Iterate over a list safely
 * @pos: the iterator
 * @n: temporary storage
 * @head: the list to iterate over
 *
 * This is safe to use if @pos could be removed from the list in the body of
 * the loop.
 */
#define list_for_each_safe(pos, n, head)			\
	for (pos = (head)->next, n = pos->next; pos != (head);	\
		pos = n, n = pos->next)

/**
 * define list_for_each_entry_continue - Iterate continuing after existing point
 * @pos:    the type * to use as a loop counter
 * @head:   the list head
 * @member: the name of the list_struct within the struct
 *
 * Iterate over a list continuing after existing point
 */
#define list_for_each_entry_continue(pos, head, member)			\
	for (pos = list_entry(pos->member.next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head); i	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * DOC: hlist Hash List
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is too
 * wasteful.  You lose the ability to access the tail in O(1).
 */

/**
 * struct hlist_node - node for hlist
 * @next: next item
 * @pprev: previous item
 */
struct hlist_node {
	struct hlist_node *next, **pprev;
};

/**
 * struct hlist_head - Head of list
 * @first: head item
 */
struct hlist_head {
	struct hlist_node *first;
};

/*
 * "NULL" might not be defined at this point
 */
#ifdef NULL
#define NULL_P NULL
#else
#define NULL_P ((void *)0)
#endif

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

	if (next->next)
		next->next->pprev  = &next->next;
}

#define hlist_entry(ptr, type, member) container_of(ptr, type, member)

#define hlist_for_each(pos, head)					\
	for (pos = (head)->first; pos && (prefetch(pos->next), 1);	\
	     pos = pos->next)

#define hlist_for_each_safe(pos, n, head)				\
	for (pos = (head)->first; pos && (n = pos->next, 1);		\
	     pos = n)

/**
 * define hlist_for_each_entry - Iterate over an hlist of given type
 * @tpos: the type * to use as a loop counter.
 * @pos: the &struct hlist_node to use as a loop counter.
 * @head: the head for your list.
 * @member: the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(tpos, pos, head, member)			  \
	for (pos = (head)->first;					  \
	     pos && ({ prefetch(pos->next); 1; }) &&			  \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; }); \
	     pos = pos->next)

/**
 * define hlist_for_each_entry_continue - Iterate continuing after existing point
 * @tpos: the type * to use as a loop counter.
 * @pos: the &struct hlist_node to use as a loop counter.
 * @member: the name of the hlist_node within the struct.
 *
 * Iterate over an hlist continuing after existing point
 */
#define hlist_for_each_entry_continue(tpos, pos, member)		  \
	for (pos = (pos)->next;						  \
	     pos && ({ prefetch(pos->next); 1; }) &&			  \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; }); \
	     pos = pos->next)

/**
 * define hlist_for_each_entry_from - Iterate continuing from an existing point
 * @tpos: the type * to use as a loop counter.
 * @pos: the &struct hlist_node to use as a loop counter.
 * @member: the name of the hlist_node within the struct.
 *
 * Iterate over an hlist continuing from an existing point
 */
#define hlist_for_each_entry_from(tpos, pos, member)			 \
	for (; pos && ({ prefetch(pos->next); 1; }) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; });\
	     pos = pos->next)

/**
 * define hlist_for_each_entry_safe - Iterate an hlist safely
 * @tpos: the type * to use as a loop counter.
 * @pos: the &struct hlist_node to use as a loop counter.
 * @n: another &struct hlist_node to use as temporary storage
 * @head: the head for your list.
 * @member: the name of the hlist_node within the struct.
 *
 * Iterate over an hlist of given type safe against removal of list entry
 */
#define hlist_for_each_entry_safe(tpos, pos, n, head, member)		  \
	for (pos = (head)->first;					  \
	     pos && ({ n = pos->next; 1; }) &&				  \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; }); \
	     pos = n)

/**
 * define list_for_each_prev - Iterate over a list in reverse order
 * @pos: the &struct list_head to use as a loop counter.
 * @head: the head for your list.
 */
#define list_for_each_prev(pos, head)					\
	for (pos = (head)->prev, prefetch(pos->prev); pos != (head);	\
		pos = pos->prev, prefetch(pos->prev))

/**
 * define list_for_each_entry - Iterate over a list of given type
 * @pos: the type * to use as a loop counter.
 * @head: the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry((head), typeof(*pos), member),	\
		     prefetch(pos->member.next);			\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, typeof(*pos), member),	\
	     prefetch(pos->member.next))

/**
 * define list_for_each_entry_reverse - Iterate backwards over a list
 * @pos: the type * to use as a loop counter.
 * @head: the head for your list.
 * @member: the name of the list_struct within the struct.
 *
 * Iterate backwards over a list of given type.
 */
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, typeof(*pos), member);	\
	     prefetch(pos->member.prev), &pos->member != (head);	\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))

/**
 * define list_for_each_entry_safe - Iterate over a list of given type safe
 * 				     against removal of list entry
 * @pos: the type * to use as a loop counter.
 * @n: another type * to use as temporary storage
 * @head: the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)			 \
	for (pos = list_first_entry((head), typeof(*pos), member),	 \
		n = list_entry(pos->member.next, typeof(*pos), member);	 \
	     &pos->member != (head);					 \
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

/**
 * define list_for_each_entry_safe_reverse - Iterate backwards over a list of
 * 					     given type safely against removal
 * 					     of entry
 * @pos: the type * to use as a loop counter.
 * @n: another type * to use as temporary storage
 * @head: the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_entry((head)->prev, typeof(*pos), member),	\
		n = list_entry(pos->member.prev, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.prev, typeof(*n), member))

#endif /* __LIBCFS_UTIL_LIST_H__ */
