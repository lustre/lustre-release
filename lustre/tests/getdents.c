#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

int main(int argc, char **argv)
{
        DIR *dir;
        struct dirent64 *entry;

        if (argc < 2) {
                fprintf(stderr, "Usage: %s dirname\n", argv[0]);
                return 1;
        }

        dir = opendir(argv[1]);
        if (!dir) {
                int rc = errno;
                perror("opendir");
                return rc;
        }

        while ((entry = readdir64(dir))) {
                puts(entry->d_name);
        }
        
        closedir(dir);

        return 0;
}
                
