#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <liblustre.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_lite.h>
#include <linux/obd_lov.h>

int main(int argc, char **argv)
{
        int fd; 

        if (argc != 2) { 
                printf("Usage %s <filename>\n", argv[0]); 
                exit(1);
        }

        fd = open(argv[1], O_RDONLY | O_LOV_DELAY_CREATE);
        if (fd == -1) { 
                printf("Error opening %s\n", argv[1]);
                exit(1);
        }

        return 0;
}
