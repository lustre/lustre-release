#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include "lshowmount.h"
#include "hash.h"
#include "hostlist.h"

#define PROGNAME "lshowmount"

extern int errno;
static int enumerate = 0;
static int lookup    = 0;
static int verbose   = 0;

static int totalexports = 0;
static int totalfailures = 0;

static struct option long_options[] = {
    {"enumerate", 0, 0, 'e'},
    {"help",      0, 0, 'h'},
    {"lookup",    0, 0, 'l'},
    {"verbose",   0, 0, 'v'},
    {0, 0, 0, 0}
};

inline int
lshowmount_hash_strcmp(const void *key1, const void *key2)
{
    return strcmp((char *) key1, (char *) key2);
}

inline void
lshowmount_hash_hostlist_freeitem(void *data)
{
    hostlist_t hl = NULL;

    if (data == NULL) {
        return;
    }

    hl = (hostlist_t) data;
    hostlist_destroy(hl);
}

inline int
is_ipaddress(const char *str)
{
    int rc = 0;
    int quad[4];

    rc = sscanf(str, "%d.%d.%d.%d", &quad[0], &quad[1], &quad[2], &quad[3]);
    if (rc == 4) {
        return 1;
    }
    return 0;
}

inline void
lshowmount_gethostname(const char *src, char *dst, int dstsize)
{
    struct hostent *hostptr = NULL;
    char tmpsrc[4];
    int rc = 0;

    memset(dst, 0, sizeof(char) * dstsize);
    if (lookup && is_ipaddress(src)) {
        rc = inet_pton(AF_INET, src, tmpsrc);

        if (rc <= 0) {
            strncpy(dst, src, dstsize);
            return;
        }
        else {
            hostptr = gethostbyaddr(tmpsrc, 4, AF_INET);
            if (hostptr == NULL) {
                strncpy(dst, src, dstsize);
                return;
            }
            else {
                strncpy(dst, hostptr->h_name, dstsize);
                return;
            }
        }
    }
    strncpy(dst, src, dstsize);
}

void
lshowmount_print_hosts(char** network,
                       hash_t network_hash)
{
    hostlist_t hl = NULL;
    hostlist_iterator_t itr = NULL;
    char *hosts = NULL;
    int numnets = 0, numhosts = 0, i = 0;

    if (network == NULL || network_hash == NULL) {
        return;
    }

    numnets = hash_count(network_hash);
    for (i = 0; i < numnets; i++) {
        errno = 0;
        hl = hash_remove(network_hash, network[i]);
        if (hl == NULL) {
            continue;
        }
        hostlist_uniq(hl);
        numhosts = hostlist_count(hl);

        if (numhosts > 0) {
            if (enumerate) {
                itr = hostlist_iterator_create(hl);

                /* setup argument */
                while ((hosts = hostlist_next(itr)) != NULL) {
                    printf("    %s@%s\n", hosts, network[i]);
                }
                hostlist_iterator_destroy(itr);
            }
            else {
                hosts = malloc(sizeof(char) * (numhosts) * (NID_MAX+1));
                if (hosts == NULL) {
                    fprintf(stderr, "warning: could not allocate buffer "
                                    "to print hostrange\n");
                    return;
                }
                hostlist_ranged_string(hl, sizeof(char) *
                                           numhosts *
                                           (NID_MAX+1), hosts);
                printf("    %s@%s\n", hosts, network[i]);
                free(hosts);
                hosts = NULL;
            }
        }
        memset(network[i], 0, sizeof(char) * (LNET_NETWORK_TYPE_MAX+1));
        lshowmount_hash_hostlist_freeitem(hl);
    }
}

void usage(void)
{
	fprintf(stderr, "usage: %s [-e] [-h] [-l] [-v]\n", PROGNAME);
}

int getclients(char*  procpath,
               char** network,
               hash_t network_hash)
{
    DIR *dirp, *dirp2;
    struct dirent *dp, *dp2;
    char path[PATH_MAX+1];
    char nid[NID_MAX+1], addr[NID_MAX+1];
    int size = PATH_MAX+1, sizeleft, sizeleft2;
    int tmplen, tmplen2, idx, rc = 0;
    char *tmp, *tmp2;
    hostlist_t hl;

    if (procpath == NULL) {
        return -1;
    }

    /* It is not an error if we cannot open
     * procpath since we are not sure if this
     * node is an mgs, mds, and/or oss */
    errno = 0;
    dirp = opendir(procpath);
    if (dirp == NULL) {
        return 0;
    }

    do {
        errno = 0;
        dp = readdir(dirp);
        if (dp != NULL) {
            if (dp->d_type != DT_DIR ||
                strncmp(dp->d_name, ".", 2) == 0  ||
                strncmp(dp->d_name, "..", 3) == 0) {
                continue;
            }

            sizeleft = size;
            tmp = path;
            memset(tmp, 0, sizeof(char) * sizeleft);

            strncpy(tmp, procpath, sizeleft);
            tmplen = strnlen(tmp, sizeleft);
            sizeleft -= tmplen;
            tmp += tmplen;

            strncpy(tmp, "/", sizeleft);
            tmplen = strnlen(tmp, sizeleft);
            sizeleft -= tmplen;
            tmp += tmplen;

            strncpy(tmp, dp->d_name, sizeleft);
            tmplen = strnlen(tmp, sizeleft);
            sizeleft -= tmplen;
            tmp += tmplen;

            strncpy(tmp, "/", sizeleft);
            tmplen = strnlen(tmp, sizeleft);
            sizeleft -= tmplen;
            tmp += tmplen;

            strncpy(tmp, PROC_EXPORTS, sizeleft);
            tmplen = strnlen(tmp, sizeleft);
            sizeleft -= tmplen;
            tmp += tmplen;

            errno = 0;
            dirp2 = opendir(path);
            if (dirp2 == NULL) {
                fprintf(stderr, "error: could not open: %s\n", path);
                rc = errno;
                continue;
            }

            do {
                errno = 0;
                dp2 = readdir(dirp2);
                if (dp2 != NULL) {
                    if (strncmp(dp2->d_name, ".", 2) == 0  ||
                        strncmp(dp2->d_name, "..", 3) == 0 ||
                        dp2->d_type != DT_DIR) {
                        continue;
                    }
                    totalexports++;

                    sizeleft2 = sizeleft;
                    tmp2 = tmp;
                    memset(tmp2, 0, sizeof(char) * sizeleft2);

                    strncpy(tmp2, "/", sizeleft2);
                    tmplen2 = strnlen(tmp2, sizeleft2);
                    sizeleft2 -= tmplen2;
                    tmp2 += tmplen2;

                    strncpy(tmp2, dp2->d_name, sizeleft2);
                    tmplen2 = strnlen(tmp2, sizeleft2);
                    sizeleft2 -= tmplen2;
                    tmp2 += tmplen2;

                    memset(nid, 0, sizeof(char) * (NID_MAX+1));
                    strncpy(nid, basename(path), sizeof(char) * (NID_MAX+1));
                    tmp2 = strrchr(nid, '@');
                    if (tmp2 == NULL) {
                        totalfailures++;
                        continue;
                    }
                    *tmp2 = '\0';
                    tmp2++;
                    /* Note that tmp2 should now hold the lnet network */

                    /* Check to see if this lnet network already has a hostset
                     * associated with it */
                    errno = 0;
                    hl = hash_find(network_hash, tmp2);
                    if (hl == NULL) {
                        if (hash_count(network_hash) >= NETWORK_MAX) {
                            (void)closedir(dirp2);
                            return EINVAL;
                        }

                        /* Create a new hostset for this hash table and
                         * insert the first part of the nid into it */
                        idx = hash_count(network_hash);
                        strncpy(network[idx], tmp2, LNET_NETWORK_TYPE_MAX);
                        lshowmount_gethostname(nid, addr, NID_MAX+1);
                        hl = hostlist_create(addr);
                        hash_insert(network_hash, network[idx], hl);
                    }
                    else {
                        lshowmount_gethostname(nid, addr, NID_MAX+1);
                        hostlist_push_host(hl, addr);
                    }
                }
            } while (dp2 != NULL);
            (void) closedir(dirp2);

            /* If the verbose option is set we want to print
             * out the hostlist for each mgs, mds, obdfilter */
            if (verbose) {
                printf("%s:\n", dp->d_name);
                if (totalfailures > 0) {
                    fprintf(stderr, "failures %d of %d exports\n",
                            totalfailures, totalexports);
                }

                if (!rc && totalfailures > 0) {
                    rc = 1;
                }

                totalexports = totalfailures = 0;
                lshowmount_print_hosts(network, network_hash);
            }
        }
    } while (dp != NULL);
    (void) closedir(dirp);

    if (!rc && totalfailures > 0) {
        rc = 1;
    }

    return rc;
}

int main(int argc, char **argv)
{
    int                 opt = 0;
    int                 optidx = 0;
    int                 i = 0, rc = 0, rc2 = 0, rc3 = 0;
    hash_t              network_hash = NULL;
    char**              network = NULL;

    while ((opt = getopt_long(argc, argv, "ehlv",long_options, &optidx)) != -1) {
        switch (opt) {
            case 'e':
                enumerate = 1;
                break;
            case 'h':
                usage();
                goto finish;
                break;
            case 'l':
                lookup = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                usage();
                rc = -1;
                goto finish;
                break;
        }
    }

    /* Allocate memory for NETWORK_MAX total possible
     * lnet networks.  Each network will have its own
     * hash table so that we can possibly create a ranged
     * string for it */
    network = malloc(sizeof(char *) * NETWORK_MAX);
    if (network == NULL) {
        rc = ENOMEM;
        goto finish;
    }
    memset(network, 0, sizeof(char *) * NETWORK_MAX);
    for (i = 0; i < NETWORK_MAX; i++) {
        network[i] = malloc(sizeof(char) * (LNET_NETWORK_TYPE_MAX+1));
        if (network[i] == NULL) {
            rc = ENOMEM;
            goto finish;
        }
        memset(network[i], 0, sizeof(char) * (LNET_NETWORK_TYPE_MAX+1));
    }

    /* Initialize the network_hash.  This hash table will map
     * a particular network say elan1 or tcp2 to a hostset */
    network_hash = hash_create(0,
                               (hash_key_f) hash_key_string,
                               lshowmount_hash_strcmp,
                               lshowmount_hash_hostlist_freeitem);

    rc  = getclients(PROC_DIR_MGS, network, network_hash);
    rc2 = getclients(PROC_DIR_MDS, network, network_hash);
    rc3 = getclients(PROC_DIR_OST, network, network_hash);
    if (rc || rc2 || rc3) {
        rc = rc2 > rc ? rc2 : rc;
        rc = rc3 > rc ? rc3 : rc;
    }

    if (!verbose) {
        if (totalfailures > 0) {
            fprintf(stderr, "failures %d of %d exports\n",
                    totalfailures, totalexports);
        }
        lshowmount_print_hosts(network, network_hash);
    }

finish:
    hash_destroy(network_hash);
    if (network != NULL) {
        for (i = 0; i < NETWORK_MAX; i++) {
            if (network[i] != NULL) {
                free(network[i]);
                network[i] = NULL;
            }
        }
        free(network);
        network = NULL;
    }

    return rc;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
