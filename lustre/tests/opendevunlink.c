/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

int main(int argc, char **argv)
{
        char *dname1, *dname2;
        int fddev1, fddev2, rc;
        //DIR *dp;
        struct stat st1, st2;

        if (argc < 2 || argc > 3) {
                fprintf(stderr, "usage: %s filename1 [filename2]\n", argv[0]);
                exit(1);
        }

        dname1 = argv[1];
        if (argc == 3)
                dname2 = argv[2];
        else
                dname2 = argv[1];

        //create the special file (right now only test on pipe)
        fprintf(stderr, "creating special file %s\n", dname1);
        rc = mknod(dname1, 0777|S_IFIFO, 0);
        if (rc == -1) {
                fprintf(stderr, "creating %s fails: %s\n", 
                        dname1, strerror(errno));
                exit(1);
        }

        // open the special file again
        fprintf(stderr, "opening file\n");
        fddev1 = open(dname1, O_RDONLY | O_NONBLOCK);
        if (fddev1 == -1) {
                fprintf(stderr, "open %s fails: %s\n",
                        dname1, strerror(errno));
                exit(1);
        }
        
        // doesn't matter if the two dirs are the same??
        fddev2 = open(dname2, O_RDONLY | O_NONBLOCK);
        if (fddev2 == -1) {
                fprintf(stderr, "open %s fails: %s\n",
                        dname2, strerror(errno));
                exit(1);
        }
        
        // delete the special file
        fprintf (stderr, "unlinking %s\n", dname1);
        rc = unlink(dname1);
        if (rc) {
                fprintf(stderr, "unlink %s error: %s\n", 
                        dname1, strerror(errno));
                exit(1);
        }

        if (access(dname2, F_OK) == 0){
                fprintf(stderr, "%s still exists\n", dname2);
                exit(1);
        }

        if (access(dname1, F_OK) == 0){
                fprintf(stderr, "%s still exists\n", dname1);
                exit(1);
        }

        // fchmod one special file
        rc = fchmod (fddev1, 0777);
        if(rc == -1)
        {
                fprintf(stderr, "fchmod unlinked special file %s fails: %s\n", 
                        dname1, strerror(errno));
                exit(1);
        }
                
        // fstat two files to check if they are the same
        rc = fstat(fddev1, &st1);
        if(rc == -1)
        {
                fprintf(stderr, "fstat unlinked special file %s fails: %s\n", 
                        dname1, strerror(errno));
                exit(1);
        }

        rc = fstat(fddev2, &st2);
        if (rc == -1) {
                fprintf(stderr, "fstat file %s fails: %s\n",
                        dname2, strerror(errno));
                exit(1);
        }

        if (st1.st_mode != st2.st_mode) {  // can we do this?
                fprintf(stderr, "fstat different value on %s and %s\n",                                 dname1, dname2);
                exit(1);
        }        

        fprintf(stderr, "Ok, everything goes well.\n");
        return 0;
}

