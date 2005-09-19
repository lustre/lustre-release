#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
        mode_t mode;

        if (argc != 3) { 
                printf("usage: %s mode name\n", argv[0]);
                return 1;
        }

        mode = strtoul(argv[1], NULL, 8); 
        return chmod(argv[2], mode) ? errno : 0;
}
