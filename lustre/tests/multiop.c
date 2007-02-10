/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#define _GNU_SOURCE /* pull in O_DIRECTORY in bits/fcntl.h */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#define T1 "write data before unlink\n"
#define T2 "write data after unlink\n"
char buf[] = "yabba dabba doo, I'm coming for you, I live in a shoe, I don't know what to do.\n'Bigger, bigger,and bigger yet!' cried the Creator.  'You are not yet substantial enough for my boundless intents!'  And ever greater and greater the object became, until all was lost 'neath its momentus bulk.\n";

char usage[] = 
"Usage: %s filename command-sequence\n"
"    command-sequence items:\n"
"        c  close\n"
"        d  mkdir\n"
"        D  open(O_DIRECTORY)\n"
"        L  link\n"
"        l  symlink\n"
"        m  mknod\n"
"        M  rw mmap to EOF (must open and stat prior)\n"
"        N  rename\n"
"        o  open(O_RDONLY)\n"
"        O  open(O_CREAT|O_RDWR)\n"
"        r[num] read [optional length]\n"
"        R  reference entire mmap-ed region\n"
"        s  stat\n"
"        S  fstat\n"
"        t  fchmod\n"
"        T[num] ftruncate [optional position, default 0]\n"
"        u  unlink\n"
"        U  munmap\n"
"        w[num] write optional length\n"
"        W  write entire mmap-ed region\n"
"        y  fsync\n"
"        Y  fdatasync\n"
"        z[num] seek [optional position, default 0]\n"
"        _  wait for signal\n";

static int usr1_received;
void usr1_handler(int unused)
{
        usr1_received = 1;
}

static const char *
pop_arg(int argc, char *argv[])
{
        static int cur_arg = 3;

        if (cur_arg >= argc)
                return NULL;

        return argv[cur_arg++];
}
#define POP_ARG() (pop_arg(argc, argv))
#define min(a,b) ((a)>(b)?(b):(a))

int main(int argc, char **argv)
{
        char *fname, *commands;
        const char *newfile;
        struct stat st;
        size_t mmap_len = 0, i;
        unsigned char *mmap_ptr = NULL, junk = 0;
        int rc, len, fd = -1;

        if (argc < 3) {
                fprintf(stderr, usage, argv[0]);
                exit(1);
        }

        signal(SIGUSR1, usr1_handler);

        fname = argv[1];

        for (commands = argv[2]; *commands; commands++) {
                switch (*commands) {
                case '_':
                        if (usr1_received == 0)
                                pause();
                        usr1_received = 0;
                        signal(SIGUSR1, usr1_handler);
                        break;
                case 'c':
                        if (close(fd) == -1) {
                                perror("close");
                                exit(1);
                        }
                        fd = -1;
                        break;
                case 'd':
                        if (mkdir(fname, 0755) == -1) {
                                perror("mkdir(0755)");
                                exit(1);
                        }
                        break;
                case 'D':
                        fd = open(fname, O_DIRECTORY);
                        if (fd == -1) {
                                perror("open(O_DIRECTORY)");
                                exit(1);
                        }
                        break;
                case 'l':
                        newfile = POP_ARG();
                        if (!newfile)
                                newfile = fname;
                        if (symlink(fname, newfile)) {
                                perror("symlink()");
                                exit(1);
                        }
                        break;
                case 'L':
                        newfile = POP_ARG();
                        if (!newfile)
                                newfile = fname;
                        if (link(fname, newfile)) {
                                perror("symlink()");
                                exit(1);
                        }
                        break;
                case 'm':
                        if (mknod(fname, S_IFREG | 0644, 0) == -1) {
                                perror("mknod(S_IFREG|0644, 0)");
                                exit(1);
                        }
                        break;
                case 'M':
                        mmap_len = st.st_size;
                        mmap_ptr = mmap(NULL, mmap_len, PROT_WRITE | PROT_READ,
                                        MAP_SHARED, fd, 0);
                        if (mmap_ptr == MAP_FAILED) {
                                perror("mmap");
                                exit(1);
                        }
                        break;
                case 'N':
                        newfile = POP_ARG();
                        if (!newfile)
                                newfile = fname;
                        if (rename (fname, newfile)) {
                                perror("rename()");
                                exit(1);
                        }
                        break;
                case 'O':
                        fd = open(fname, O_CREAT|O_RDWR, 0644);
                        if (fd == -1) {
                                perror("open(O_RDWR|O_CREAT)");
                                exit(1);
                        }
                        break;
                case 'o':
                        fd = open(fname, O_RDONLY);
                        if (fd == -1) {
                                perror("open(O_RDONLY)");
                                exit(1);
                        }
                        break;
                case 'r': 
                        len = atoi(commands+1);
                        if (len <= 0)
                                len = 1;
                        while(len > 0) {
                                if (read(fd, &buf,
                                         min(len,sizeof(buf))) == -1) {
                                        perror("read");
                                        exit(1);
                                }
                                len -= sizeof(buf);
                        }
                        break;
                case 'S':
                        if (fstat(fd, &st) == -1) {
                                perror("fstat");
                                exit(1);
                        }
                        break;
                case 'R':
                        for (i = 0; i < mmap_len && mmap_ptr; i += 4096)
                                junk += mmap_ptr[i];
                        break;
                case 's':
                        if (stat(fname, &st) == -1) {
                                perror("stat");
                                exit(1);
                        }
                        break;
                case 't':
                        if (fchmod(fd, 0) == -1) {
                                perror("fchmod");
                                exit(1);
                        }
                        break;
                case 'T':
                        len = atoi(commands+1);
                        if (ftruncate(fd, len) == -1) {
                                printf("ftruncate (%d,%d)\n", fd, len);
                                perror("ftruncate");
                                exit(1);
                        }
                        break;
                case 'u':
                        if (unlink(fname) == -1) {
                                perror("unlink");
                                exit(1);
                        }
                        break;
                case 'U':
                        if (munmap(mmap_ptr, mmap_len)) {
                                perror("munmap");
                                exit(1);
                        }
                        break;
                case 'w': 
                        len = atoi(commands+1);
                        if (len <= 0)
                                len = 1;
                        while(len > 0) {
                                if ((rc = write(fd, buf, 
                                                min(len, sizeof(buf))))
                                    == -1) {
                                        perror("write");
                                        exit(1);
                                }
                                len -= sizeof(buf);
                        }
                        break;
                case 'W':
                        for (i = 0; i < mmap_len && mmap_ptr; i += 4096)
                                mmap_ptr[i] += junk++;
                        break;
                case 'y':
                        if (fsync(fd) == -1) {
                                perror("fsync");
                                exit(1);
                        }
                        break;
                case 'Y':
                        if (fdatasync(fd) == -1) {
                                perror("fdatasync");
                                exit(1);
                        }
                case 'z':
                        len = atoi(commands+1);
                        if (lseek(fd, len, SEEK_SET) == -1) {
                                perror("lseek");
                                exit(1);
                        }
                        break;
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                        break;
                default:
                        fprintf(stderr, "unknown command \"%c\"\n", *commands);
                        fprintf(stderr, usage, argv[0]);
                        exit(1);
                }
        }

        return 0;
}
