/*
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
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
 *
 */

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

/*
 * Windows generic table support routines
 */

#define TAG_RADIX_TABLE 'XIDR'
typedef struct _RADIX_TABLE_ELEMENT {
    ULONG       Key;
    PVOID       Value;
} RADIX_TABLE_ELEMENT, *PRADIX_TABLE_ELEMENT;


RTL_GENERIC_COMPARE_RESULTS
RadixCompareElement (
    IN PRTL_GENERIC_TABLE   Table,
    IN PVOID                Index1,
    IN PVOID                Index2
    )
{
    ULONG   Key1, Key2;

    Key1 = *((ULONG UNALIGNED *) Index1);
    Key2 = *((ULONG UNALIGNED *) Index2);

    if (Key1 < Key2) {
        return GenericLessThan;
    } else if (Key1 > Key2) {
        return GenericGreaterThan;
    }

    return GenericEqual;
}

PVOID
RadixAllocateElement (
    IN PRTL_GENERIC_TABLE   Table,
    IN CLONG                Size
    )
{
    return FsRtlAllocatePoolWithTag(NonPagedPool,Size, TAG_RADIX_TABLE);
}

VOID
RadixDestroyElement (
    IN PRTL_GENERIC_TABLE   Table,
    IN PVOID                Buffer
    )
{
    ExFreePoolWithTag(Buffer, TAG_RADIX_TABLE);
}


PVOID
RadixInsertElement(
    IN PRTL_GENERIC_TABLE   Table,
    IN ULONG                Key,
    IN PVOID                Value
    )
{
    RADIX_TABLE_ELEMENT element;
    element.Key = Key;
    element.Value = Value;
    return RtlInsertElementGenericTable( Table, &element, 
                      sizeof(RADIX_TABLE_ELEMENT), NULL );
}

BOOLEAN
RadixDeleteElement(
    IN PRTL_GENERIC_TABLE   Table,
    IN ULONG                Key
    )
{
    RADIX_TABLE_ELEMENT element;
    element.Key = Key;
    return RtlDeleteElementGenericTable(Table, &element);
}


PRADIX_TABLE_ELEMENT
RadixLookupElement (
    IN PRTL_GENERIC_TABLE   Table,
    IN ULONG                Key
    )
{
    RADIX_TABLE_ELEMENT     element;

    element.Key = Key;
    return (PRADIX_TABLE_ELEMENT) 
            RtlLookupElementGenericTable(Table, &element);
}

PRADIX_TABLE_ELEMENT
RadixGetNextElement (
    IN PRTL_GENERIC_TABLE   Table,
    IN PVOID *               Restart
    )
{
    return (PRADIX_TABLE_ELEMENT)
            RtlEnumerateGenericTableWithoutSplaying(Table, Restart);
}



VOID
RadixInitTable(
    IN PRTL_GENERIC_TABLE   Table
    )
{
    
    /*  initialize rafix generic table. */

    RtlInitializeGenericTable(
        Table,
        RadixCompareElement,
        RadixAllocateElement,
        RadixDestroyElement,
        NULL
        );
}

VOID
RadixDestroyTable(
    IN PRTL_GENERIC_TABLE   Table
    )
{
    PRADIX_TABLE_ELEMENT element;
    PVOID                restart = NULL;

Again:
    element = (PRADIX_TABLE_ELEMENT) RadixGetNextElement(Table, &restart);
    if (element) {
        RadixDeleteElement(Table, element->Key);
        goto Again;
    }
}

/*
 *  Radix Tree Suppoert Rotuines
 * 
 */

/**
 *	radix_tree_gang_lookup - perform multiple lookup on a radix tree
 *	\param root radix tree root
 *	\param results where the results of the lookup are placed
 *	\param first_index start the lookup from this key
 *	\param max_items place up to this many items at *results
 *
 *	Performs an index-ascending scan of the tree for present items.  Places
 *	them at * \a results and returns the number of items which were placed at
 *	*\a results.
 *
 */
unsigned int
radix_tree_gang_lookup(struct radix_tree_root *root, void **results,
			unsigned long first_index, unsigned int max_items)
{
    PRADIX_TABLE_ELEMENT element;
    PVOID                restart = NULL;
    unsigned int         i = 0;

    element = RadixLookupElement(&root->table, first_index);
    restart = element;
    while (element && i < max_items) {
        results[i++] = element->Value; 
        element = RadixGetNextElement(&root->table, &restart);
    }

    return i;
}


/**
 *	radix_tree_lookup    -    perform lookup operation on a radix tree
 *	\param root radix tree root
 *	\param index index key
 *
 *	Lookup the item at the position \a index in the radix tree \a root.
 *
 */
void *radix_tree_lookup(struct radix_tree_root *root, unsigned long index)
{
    PRADIX_TABLE_ELEMENT element;
    int                  i = 0;

    element = RadixLookupElement(&root->table, index);
    if (element) {
        return element->Value;
    }

    return NULL;
}

/**
 *	radix_tree_insert    -    insert into a radix tree
 *	\param root radix tree root
 *	\param index index key
 *	\param item item to insert
 *
 *	Insert an item into the radix tree at position \a index.
 */
int radix_tree_insert(struct radix_tree_root *root,
			unsigned long index, void *item)
{
    if (RadixInsertElement(&root->table, index, item)) {
        return 0;
    }

    return -ENOMEM;
}

/**
 *	radix_tree_delete    -    delete an item from a radix tree
 *	\param root radix tree root
 *	\param index index key
 *
 *	Remove the item at \a index from the radix tree rooted at \a root.
 *
 *	Returns the address of the deleted item, or NULL if it was not present.
 */
void *radix_tree_delete(struct radix_tree_root *root, unsigned long index)
{
    RadixDeleteElement(&root->table, index);
    return NULL;
}
