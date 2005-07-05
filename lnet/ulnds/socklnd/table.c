/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *  Copyright (c) 2002 Eric Hoffman
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
 */

#include <table.h>
#include <stdlib.h>
#include <string.h>


/* table.c:
 * a very simple hash table implementation with paramerterizable 
 * comparison and key generation functions. it does resize
 * in order to accomidate more entries, but never collapses 
 * the table 
 */

static table_entry *table_lookup (table t,void *comparator,
                                  unsigned int k,
                                  int (*compare_function)(void *, void *),
                                  int *success)
{
    unsigned int key=k%t->size;
    table_entry *i;

    for (i=&(t->entries[key]);*i;i=&((*i)->next)){
        if (compare_function && ((*i)->key==k))
            if ((*t->compare_function)((*i)->value,comparator)){
                *success=1;
                return(i);
            }
    }
    *success=0;
    return(&(t->entries[key]));
}


static void resize_table(table t, int size)
{
    int old_size=t->size;
    table_entry *old_entries=t->entries;
    int i; 
    table_entry j,n;
    table_entry *position;
    int success;
  
    t->size=size;
    t->entries=(table_entry *)malloc(sizeof(table_entry)*t->size);
    memset(t->entries,0,sizeof(table_entry)*t->size);

    for (i=0;i<old_size;i++)
        for (j=old_entries[i];j;j=n){
            n=j->next;
            position=table_lookup(t,0,j->key,0,&success);
            j->next= *position;
            *position=j;
        }
    free(old_entries);
}


/* Function: key_from_int
 * Arguments: int i: value to compute the key of
 * Returns: the key 
 */
unsigned int key_from_int(int i)
{
    return(i);
}


/* Function: key_from_string
 * Arguments: char *s: the null terminated string
 *                     to compute the key of
 * Returns: the key 
 */
unsigned int key_from_string(char *s)
{
    unsigned int result=0;
    unsigned char *n;
    int i;
    if (!s) return(1);
    for (n=s,i=0;*n;n++,i++) result^=(*n*57)^*n*i;
    return(result);
}


/* Function: hash_create_table
 * Arguments: compare_function: a function to compare
 *                              a table instance with a correlator
 *            key_function: a function to generate a 32 bit 
 *                          hash key from a correlator
 * Returns: a pointer to the new table
 */
table hash_create_table (int (*compare_function)(void *, void *),
                    unsigned int (*key_function)(void *))
{
    table new=(table)malloc(sizeof(struct table));
    memset(new, 0, sizeof(struct table));

    new->compare_function=compare_function;
    new->key_function=key_function;
    new->number_of_entries=0;
    new->size=4;
    new->entries=(table_entry *)malloc(sizeof(table_entry)*new->size);
    memset(new->entries,0,sizeof(table_entry)*new->size);
    return(new);
}


/* Function: hash_table_find
 * Arguments: t: a table to look in
 *            comparator: a value to access the table entry
 * Returns: the element references to by comparator, or null
 */
void *hash_table_find (table t, void *comparator)
{
    int success;
    table_entry* entry=table_lookup(t,comparator,
                                    (*t->key_function)(comparator),
                                    t->compare_function,
                                    &success);
    if (success)  return((*entry)->value);
    return(0);
}


/* Function: hash_table_insert
 * Arguments: t: a table to insert the object
 *            value: the object to put in the table
 *            comparator: the value by which the object 
 *                        will be addressed
 * Returns: nothing
 */
void hash_table_insert (table t, void *value, void *comparator)
{
    int success;
    unsigned int k=(*t->key_function)(comparator);
    table_entry *position=table_lookup(t,comparator,k,
                                       t->compare_function,&success);
    table_entry entry;

    if (success) {
        entry = *position;
    } else {
        entry = (table_entry)malloc(sizeof(struct table_entry));
        memset(entry, 0, sizeof(struct table_entry));
        entry->next= *position;
        *position=entry;
        t->number_of_entries++;
    }
    entry->value=value;
    entry->key=k;
    if (t->number_of_entries > t->size) resize_table(t,t->size*2);
}

/* Function: hash_table_remove
 * Arguments: t: the table to remove the object from
 *            comparator: the index value of the object to remove
 * Returns: 
 */
void hash_table_remove (table t, void *comparator)
{
    int success;
    table_entry temp;
    table_entry *position=table_lookup(t,comparator,
                                       (*t->key_function)(comparator),
                                       t->compare_function,&success);
    if(success) {
        temp=*position;
        *position=(*position)->next;
        free(temp); /* the value? */
        t->number_of_entries--;
    }
}

/* Function: hash_iterate_table_entries
 * Arguments: t: the table to iterate over
 *            handler: a function to call with each element
 *                     of the table, along with arg
 *            arg: the opaque object to pass to handler
 * Returns: nothing
 */
void hash_iterate_table_entries(table t,
                           void (*handler)(void *,void *), 
                           void *arg)
{
    int i;
    table_entry *j,*next;
  
    for (i=0;i<t->size;i++)
        for (j=t->entries+i;*j;j=next){
            next=&((*j)->next);
            (*handler)(arg,(*j)->value);
        }
}

/* Function: hash_filter_table_entries
 * Arguments: t: the table to iterate over
 *            handler: a function to call with each element
 *                     of the table, along with arg
 *            arg: the opaque object to pass to handler
 * Returns: nothing
 * Notes: operations on the table inside handler are not safe
 *
 * filter_table_entires() calls the handler function for each
 *   item in the table, passing it and arg. The handler function
 *   returns 1 if it is to be retained in the table, and 0
 *   if it is to be removed.
 */
void hash_filter_table_entries(table t, int (*handler)(void *, void *), void *arg)
{
    int i;
    table_entry *j,*next,v;
  
    for (i=0;i<t->size;i++)
        for (j=t->entries+i;*j;j=next){
            next=&((*j)->next);
            if (!(*handler)(arg,(*j)->value)){
                next=j;
                v=*j;
                *j=(*j)->next;
                free(v);
                t->number_of_entries--;
            }
        }
}

/* Function: destroy_table
 * Arguments: t: the table to free
 *            thunk: a function to call with each element,
 *                   most likely free()
 * Returns: nothing
 */
void hash_destroy_table(table t,void (*thunk)(void *))
{
    table_entry j,next;
    int i;
    for (i=0;i<t->size;i++)
        for (j=t->entries[i];j;j=next){
            next=j->next;
            if (thunk) (*thunk)(j->value);
            free(j);
        }
    free(t->entries);
    free(t);
}
