#include <stdio.h>
#include <errno.h>
#include <sys/utsname.h>
#include <string.h>

struct file_addr {
	char path[256];
	char modname[32];
	unsigned long base; 
};

int print_symbol_address(struct file_addr * fa)
{
        char buffer[4096];
        char cmd[256];
        char func_name[256];
	unsigned long addr;
	char mode[256];
        FILE *file;

	sprintf(cmd, "modprobe -l %s", fa->modname);
        file = popen(cmd, "r");
        if (!file) {
                printf("failed to execute %s:%s\n."
		       "Have you installed modules?\n", 
			cmd, strerror(errno));
		pclose(file);
                return -1;
        }
        if (fgets(buffer, 4095, file) == NULL) {
                printf("failed to get modprobe ouput for %s:%s\n", 
			fa->modname, strerror(errno));
		pclose(file);
                return -1;
	}
	pclose(file);

	sprintf(cmd, "nm -n %s", buffer);
        file = popen(cmd, "r");
        if (!file) {
                printf("failed to execute %s:%s\n."
		       "Have you installed modules?\n", 
			cmd, strerror(errno));
                return -1;
        }

        while (fgets(buffer, 4095, file)) {
        	if (fscanf(file, "%x %s %s\n", &addr, mode, func_name) != 3)
			continue;

		/* only list symbol in text section. */
		if (strcasecmp(mode, "t") == 0) {
			/* skip __init functoin. How to filter others? */
			if (strcmp(func_name, "init_module") != 0)
				printf("%x %s %s\n", fa->base + addr, 
					mode, func_name);
		}
	}
        pclose(file);
        return 0;
}


int generate_symbol_file()
{
        static char* cmd = "lctl modules";
        char         other[4096];
        FILE         *file;
	struct file_addr gfa;

	memset(&gfa, 0, sizeof(gfa));
        file = popen(cmd, "r");
        if (!file) {
                printf("failed to execute %s: %s\n", cmd, strerror(errno));
                return -1;
        }

        while ( fscanf(file, "%s %s %lx\n", other, gfa.path, &gfa.base) == 3) {
		strncpy(gfa.modname, strrchr(gfa.path, '/') + 1, 
			strrchr(gfa.path, '.') - strrchr(gfa.path, '/') - 1);

		 //fprintf(stderr, "%s %s %#x\n", gfa.path, gfa.modname, gfa.base);

		/* continue going without checking result */
		print_symbol_address(&gfa);
		memset(&gfa, 0, sizeof(gfa));
        }
        pclose(file);
	return 0;
}


int main() 
{
	return	generate_symbol_file();
}
