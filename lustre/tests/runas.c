/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#define DEBUG 0

void
Usage_and_abort()
{
       fprintf(stderr, "Usage: runas -u user_id [ -g grp_id ]" \
           " command_to_be_run \n");
       exit(-1);
}

// Usage: runas -u user_id [ -g grp_id ] "command_to_be_run"
// return: the return value of "command_to_be_run"
// NOTE: returning -1 might be the return code of this program itself or
// the "command_to_be_run"

// ROOT runs "runas" for free
// Other users run "runas" requires  chmod 6755 "command_to_be_run"

int 
main(int argc, char**argv)
{
        char command[1024];
        char *cmd_ptr;
        int status;
        int c,i;
        int gid_is_set = 0;
        int uid_is_set = 0;
        uid_t user_id;
        gid_t grp_id;

        if(argc == 1) {
                Usage_and_abort();
        }

        // get UID and GID
        while ((c = getopt (argc, argv, "u:g:h")) != -1) {
                switch (c) {
                case 'u':
                        user_id = (uid_t)atoi(optarg);
                        uid_is_set = 1;
                        if(!gid_is_set) {
                                  grp_id = user_id;
                        }
                 break;

                 case 'g':
                         grp_id = (gid_t)atoi(optarg);
                         gid_is_set = 1;
                 break;

                 case 'h':
                         Usage_and_abort ();
                 break;

                 default:
                 //      fprintf(stderr, "Bad parameters.\n");
                 //      Usage_and_abort ();
                 }
        }

        if (!uid_is_set){
                Usage_and_abort ();
        }
  

        if(optind == argc) {
                fprintf(stderr, "Bad parameters.\n");
                Usage_and_abort();
        }


        // assemble the command
        cmd_ptr = command ;
        for (i = optind; i < argc; i++)
                 cmd_ptr += sprintf(cmd_ptr,  "%s ", argv[i]);


#if DEBUG
  system("whoami");
#endif

        // set GID
        status = setregid(grp_id, grp_id );
        if( status == -1) {
                 fprintf(stderr, "Cannot change grp_ID to %d, errno=%d (%s)\n",
	           grp_id, errno, strerror(errno) );
                 exit(-1);
        }

        // set UID
        status = setreuid(user_id, user_id );
        if(status == -1) {
                  fprintf(stderr,"Cannot change user_ID to %d, errno=%d (%s)\n",
	            user_id, errno, strerror(errno) );
                  exit(-1);
        }

#if DEBUG
  system("whoami");
#endif

        fprintf(stdout, "running as USER(%d), Grp (%d):  \"%s\" \n", 
           user_id, grp_id, command );

        // run the command
        status = system(command);

        // pass the return code of command_to_be_run out of this wrapper
        if (status == -1) {
                 fprintf(stderr, "%s: system() command failed to run\n",
                           argv[0]);
        }
        else{
                 status = WEXITSTATUS(status);
                 fprintf(stderr, "[%s #%d] \"%s\" returns %d (%s).\n", argv[0],
                        user_id, argv[optind], status, strerror(status));

        }

        return(status);
}

