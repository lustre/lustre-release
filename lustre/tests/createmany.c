#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char ** argv)
{
        int i, rc, count;
        char filename[4096];

        if (argc < 3) { 
                printf("Usage %s filenamebase count\n", argv[0]);
                return 1;
        }

        if (strlen(argv[1]) > 4080) { 
                printf("name too long\n");
                return 1;
        }

        count = strtoul(argv[2], NULL, 0);

            
        for (i=0 ; i < count ; i++) { 
                sprintf(filename, "%s-%d", argv[1], i); 
                rc = mknod(filename, S_IFREG| 0444, 0);
                if (rc) { 
                        printf("mknod(%s) error: %s\n", 
                               filename, strerror(errno));
                        break;
                }
        }
        return rc;
} 
