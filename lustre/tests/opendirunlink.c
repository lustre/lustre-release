/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

int main(int argc, char **argv)
{
        char *dname1, *dname2;
        int fddir1, fddir2, rc;
        //DIR *dp;
        struct stat st1, st2;

        if (argc < 2 || argc > 3) {
                fprintf(stderr, "usage: %s dirname1 [dirname2]\n", argv[0]);
                exit(1);
        }

        dname1 = argv[1];
        if (argc == 3)
                dname2 = argv[2];
        else
                dname2 = argv[1];

        //create the directory
        fprintf(stderr, "creating directory %s\n", dname1);
        rc = mkdir(dname1, 0744);
        if (rc == -1) {
                fprintf(stderr, "creating %s fails: %s\n", 
                        dname1, strerror(errno));
                exit(1);
        }

        // open the dir again
        fprintf(stderr, "opening directory\n");
        fddir1 = open(dname1, O_RDONLY | O_DIRECTORY);
        if (fddir1 == -1) {
                fprintf(stderr, "open %s fails: %s\n",
                        dname1, strerror(errno));
                exit(1);
        }
        
        // doesn't matter if the two dirs are the same??
        fddir2 = open(dname2, O_RDONLY | O_DIRECTORY);
        if (fddir2 == -1) {
                fprintf(stderr, "open %s fails: %s\n",
                        dname2, strerror(errno));
                exit(1);
        }
        
        // another method
/*        
        if ( (dp = opendir(dname2)) == NULL) {
                fprintf(stderr, "opendir() %s\n", strerror(errno));
                exit(1);
        }
        fddir = dirfd(dp);
*/

        // delete the dir
        fprintf (stderr, "unlinking %s\n", dname1);
        rc = rmdir(dname1);
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

        // fchmod the dir
        rc = fchmod (fddir1, 0777);
        if(rc == -1)
        {
                fprintf(stderr, "fchmod unlinked dir fails %s\n", 
                        strerror(errno));
                exit(1);
        }
                
        // fstat two dirs to check if they are the same
        rc = fstat(fddir1, &st1);
        if(rc == -1)
        {
                fprintf(stderr, "fstat unlinked dir %s fails %s\n", 
                        dname1, strerror(errno));
                exit(1);
        }

        rc = fstat(fddir2, &st2);
        if (rc == -1) {
                fprintf(stderr, "fstat dir %s fails %s\n",
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

