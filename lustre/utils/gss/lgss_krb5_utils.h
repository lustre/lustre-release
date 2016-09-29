/*
 * Modifications for Lustre
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

#ifndef LGSS_KRB5_UTILS_H
#define LGSS_KRB5_UTILS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <krb5.h>

#include "lgss_utils.h"

extern struct lgss_mech_type lgss_mech_null;
extern struct lgss_mech_type lgss_mech_krb5;
extern struct lgss_mech_type lgss_mech_sk;

/*
 * convenient macros, these perhaps need further cleanup
 */
#ifdef HAVE_KRB5

#define KEYTAB_ENTRY_MATCH(kte, name)                                           \
        (                                                                       \
         (kte).principal->data[0].length == (sizeof(name)-1) &&                 \
         strncmp((kte).principal->data[0].data, (name), sizeof(name)-1) == 0    \
        )

#define KRB5_FREE_UNPARSED_NAME(ctx, name)                                      \
        krb5_free_unparsed_name((ctx), (name));

#define KRB5_STRDUP(str)                                                        \
        strndup((str).data, (str).length)

#define KRB5_STRCMP(str, name)                                                  \
        (                                                                       \
         (str)->length != strlen(name) ||                                       \
         strncmp((str)->data, (name), (str)->length) != 0                       \
        )

#define KRB5_STRCASECMP(str, name)                                              \
        (                                                                       \
         (str)->length != strlen(name) ||                                       \
         strncasecmp((str)->data, (name), (str)->length) != 0                   \
        )

static inline
char *lgss_krb5_strdup(krb5_data *kstr)
{
        return strndup(kstr->data, kstr->length);
}

static inline
int lgss_krb5_strcmp(krb5_data *kstr, const char *str)
{
        return (kstr->length != strlen(str) ||
                memcmp(kstr->data, str, kstr->length) != 0);
}

static inline
int lgss_krb5_strcasecmp(krb5_data *kstr, const char *str)
{
        return (kstr->length != strlen(str) ||
                strncasecmp(kstr->data, str, kstr->length) != 0);
}

#else /* !HAVE_KRB5 */

#define KEYTAB_ENTRY_MATCH(kte, name)                                           \
        (                                                                       \
         strlen((kte).principal->name.name_string.val[0]) ==                    \
         (sizeof(name)-1) &&                                                    \
         strncmp(kte.principal->name.name_string.val[0], (name),                \
                 sizeof(name)-1) == 0                                           \
        )

#define KRB5_FREE_UNPARSED_NAME(ctx, name)                                      \
        free(pname);

#define KRB5_STRDUP(str)                                                        \
        strdup(str)

#define KRB5_STRCMP(str, name)                                                  \
        strcmp((str), (name))

#define KRB5_STRCASECMP(str, name)                                              \
        strcmp((str), (name))

#endif /* HAVE_KRB5 */

#endif /* LGSS_KRB5_UTILS_H */
