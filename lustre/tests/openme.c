#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
        int fd; 

        if (argc != 2) { 
                printf("Usage openme <filename>\n"); 
                exit(1);
        }

        fd = open(argv[1], O_RDONLY | O_CREAT, 0600);
        if (fd == -1) { 
                printf("Error opening %s\n", argv[1]);
                exit(1);
        }

        sleep(10000000); 
        return 0;
}
