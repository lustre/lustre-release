/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 */

#include <table.h>

typedef struct manager {
    table connections;
    int bound;
    io_handler bound_handler;
    int (*handler)(void *, void *);
    void *handler_arg;
    unsigned short port;
} *manager;


typedef struct connection {
    unsigned int ip;
    unsigned short port;
    int fd;
    manager m;
} *connection;

connection force_tcp_connection(manager m, unsigned int ip, unsigned int short);
manager init_connections(unsigned short, int (*f)(void *, void *), void *);
void remove_connection(void *arg);
void shutdown_connections(manager m);
int read_connection(connection c, unsigned char *dest, int len);
