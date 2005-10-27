/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *  Copyright (c) 2002 Eric Hoffman
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 */

#ifndef E_TABLE
#define E_TABLE

typedef struct table_entry {
  unsigned int key;
  void *value;
  struct table_entry *next;
} *table_entry;


typedef struct table {
  unsigned int size;
  int number_of_entries;
  table_entry *entries;
  int (*compare_function)(void *, void *);
  unsigned int (*key_function)(void *);
} *table;

/* table.c */
unsigned int key_from_int(int i);
unsigned int key_from_string(char *s);
table hash_create_table(int (*compare_function)(void *, void *), 
                        unsigned int (*key_function)(void *));
void *hash_table_find(table t, void *comparator);
void hash_table_insert(table t, void *value, void *comparator);
void hash_table_remove(table t, void *comparator);
void hash_iterate_table_entries(table t, void (*handler)(void *, void *), void *arg);
void hash_filter_table_entries(table t, int (*handler)(void *, void *), void *arg);
void hash_destroy_table(table t, void (*thunk)(void *));

#endif
