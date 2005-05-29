/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

char *dir = NULL, *node = NULL, *dir2 = NULL;
long page_size;
char mmap_sanity[256];


static void usage(void)
{
        printf("Usage: mmap_sanity -d dir [-n node | -m dir2]\n");
        printf("       dir      lustre mount point\n");
        printf("       node     another client\n");
        printf("       dir2     another mount point\n");
        exit(127);
}

#define MMAP_NOTIFY_PORT        7676
static int mmap_notify(char *target, char *str, int delay)
{
	unsigned short port = MMAP_NOTIFY_PORT;
	int socket_type = SOCK_DGRAM;
	struct sockaddr_in server;
	struct hostent *hp;
	int len, sockfd, rc = 0;

        if (target == NULL)
                return 0;

	sockfd = socket(AF_INET, socket_type, 0);
	if (sockfd < 0) {
                perror("socket()");
		return errno;
	}

        if ((hp = gethostbyname(target)) == NULL) {
                perror(target);
                rc = errno;
                goto out_close;
	}

	memset(&server,0,sizeof(server));
	memcpy(&(server.sin_addr), hp->h_addr, hp->h_length);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
        
        len = sizeof(server);
        if (delay)
                sleep(delay);
        
        rc = sendto(sockfd, str, strlen(str), 0, 
                    (struct sockaddr *)&server, len);
        if (rc < 0) {
                perror("sendto()");
                rc = errno;
        } else
                rc = 0;

out_close:
        close(sockfd);
        return rc;
}

static int mmap_wait(char *str, int timeout)
{
	unsigned short port = MMAP_NOTIFY_PORT;
	int socket_type = SOCK_DGRAM;
	struct sockaddr_in local, from;
	char host[256];
	struct hostent *hp;
        fd_set rfds;
        struct timeval tv;
        int sockfd, rc = 0;

        if (dir2 != NULL)
                return 0;
        
	memset(host, 0, sizeof(host));
	if (gethostname(host, sizeof(host))) {
                perror("gethostname()");
                return errno;
	}
        
	if ((hp = gethostbyname(host)) == NULL) {
                perror(host);
                return errno;
	}

	local.sin_family = AF_INET;
	memcpy(&(local.sin_addr), hp->h_addr, hp->h_length);
	local.sin_port = htons(port);
	
	sockfd = socket(AF_INET, socket_type, 0);
	if (sockfd < 0) {
                perror("socket()");
		return errno;
	}

	rc = bind(sockfd, (struct sockaddr *)&local, sizeof(local));
        if (rc < 0) {
                perror("bind()");
                rc = errno;
                goto out_close;
	}

        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        tv.tv_sec = timeout ? timeout : 5;
        tv.tv_usec = 0;

        rc = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (rc) {       /* got data */
                char buffer[1024];
                int fromlen =sizeof(from);
                
		memset(buffer, 0, sizeof(buffer));
		rc = recvfrom(sockfd, buffer, sizeof(buffer),
                              0, (struct sockaddr *)&from,
                              (socklen_t *)&fromlen);
                if (rc <= 0) {
                        perror("recvfrom()");
                        rc = errno;
                        goto out_close;
                }
                rc = 0;

                if (strncmp(str, buffer, strlen(str)) != 0) {
                        fprintf(stderr, "expected string mismatch!\n");
                        rc = EINVAL;
                }
        } else {        /* timeout */
                fprintf(stderr, "timeout!\n");
                rc = ETIME;
        }

out_close:
        close(sockfd);
        return rc;
}

static int remote_tst(int tc, char *mnt);
static int mmap_run(char *host, int tc)
{
        pid_t child;
        char nodearg[256], command[256];
        int rc = 0;

        child = fork();
        if (child < 0)
                return errno;
        else if (child)
                return 0;

        if (dir2 != NULL) {
                rc = remote_tst(tc, dir2);
        } else {
                sprintf(nodearg, "-w %s", node);
                sprintf(command, "%s -d %s -n %s -c %d", 
                        mmap_sanity, dir, host, tc);
                rc = execlp("pdsh", "pdsh", "-S", nodearg, command, NULL);
                if (rc)
                        perror("execlp()");
        }
        _exit(rc);
}

static int mmap_initialize(char *myself, int tc)
{
        char buf[1024], *file;
        int fdr, fdw, count, rc = 0;
        
        page_size = sysconf(_SC_PAGESIZE);
        if (page_size == -1) {
                perror("sysconf(_SC_PAGESIZE)");
                return errno;
        }
        if (tc)
                return 0;

        /* copy myself to lustre for another client */
        fdr = open(myself, O_RDONLY);
        if (fdr < 0) {
                perror(myself);
                return EINVAL;
        }
        file = strrchr(myself, '/');
        if (file == NULL) {
                fprintf(stderr, "can't get test filename\n");
                close(fdr);
                return EINVAL;
        }
        file++;
        sprintf(mmap_sanity, "%s/%s", dir, file);

        fdw = open(mmap_sanity, O_CREAT|O_WRONLY, 0777);
        if (fdw < 0) {
                perror(mmap_sanity);
                close(fdr);
                return EINVAL;
        }
        while ((count = read(fdr, buf, sizeof(buf))) != 0) {
                int writes;

                if (count < 0) {
                        perror("read()");
                        rc = errno;
                        break;
                }
                writes = write(fdw, buf, count);
                if (writes != count) {
                        perror("write()");
                        rc = errno;
                        break;
                }
        }
        close(fdr);
        close(fdw);
        return rc;
}

static void mmap_finalize(int tc)
{
        if (tc)
                return;
        unlink(mmap_sanity);
}

/* basic mmap operation on single node */
static int mmap_tst1(char *mnt)
{
        char *ptr, mmap_file[256];
        int i, j, region, fd, rc = 0;

        region = page_size * 10;
        sprintf(mmap_file, "%s/%s", mnt, "mmap_file1");
        
        if (unlink(mmap_file) && errno != ENOENT) {
                perror("unlink()");
                return errno;
        }

        fd = open(mmap_file, O_CREAT|O_RDWR, 0600);
        if (fd < 0) {
                perror(mmap_file);
                return errno;
        }
        ftruncate(fd, region);

        ptr = mmap(NULL, region, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED) {
                perror("mmap()");
                rc = errno;
                goto out_close;
        }
        memset(ptr, 'a', region);

        /* mem write then sync */
        for (i = 0; i < 5; i++) {
                for (j = 0; j < region; j += page_size)
                        ptr[j] = i;
                sync();
        }

        munmap(ptr, region);
out_close:
        close(fd);
        unlink(mmap_file);
        return rc;
}

/* MAP_PRIVATE create a copy-on-write mmap */
static int mmap_tst2(char *mnt)
{
        char *ptr, mmap_file[256], buf[256];
        int fd, rc = 0;

        sprintf(mmap_file, "%s/%s", mnt, "mmap_file2");

        if (unlink(mmap_file) && errno != ENOENT) {
                perror("unlink()");
                return errno;
        }

        fd = open(mmap_file, O_CREAT|O_RDWR, 0600);
        if (fd < 0) {
                perror(mmap_file);
                return errno;
        }
        ftruncate(fd, page_size);

        ptr = mmap(NULL, page_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (ptr == MAP_FAILED) {
                perror("mmap()");
                rc = errno;
                goto out_close;
        }
        memcpy(ptr, "blah", strlen("blah"));

        munmap(ptr, page_size);
out_close:
        close(fd);
        if (rc)
                return rc;

        fd = open(mmap_file, O_RDONLY);
        if (fd < 0) {
                perror(mmap_file);
                return errno;
        }
        rc = read(fd, buf, sizeof(buf));
        if (rc < 0) {
                perror("read()");
                rc = errno;
                goto out_close;
        }
        rc = 0;
        
        if (strncmp("blah", buf, strlen("blah")) == 0) {
                fprintf(stderr, "mmap write back with MAP_PRIVATE!\n");
                rc = EFAULT;
        }
        close(fd);
        unlink(mmap_file);
        return rc;
}

/* cocurrent mmap operations on two nodes */
static int mmap_tst3(char *mnt)
{
        char *ptr, mmap_file[256], host[256];
        int region, fd, rc = 0;

        region = page_size * 100;
        sprintf(mmap_file, "%s/%s", mnt, "mmap_file3");
        
        if (unlink(mmap_file) && errno != ENOENT) {
                perror("unlink()");
                return errno;
        }

        fd = open(mmap_file, O_CREAT|O_RDWR, 0600);
        if (fd < 0) {
                perror(mmap_file);
                return errno;
        }
        ftruncate(fd, region);

        ptr = mmap(NULL, region, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED) {
                perror("mmap()");
                rc = errno;
                goto out_close;
        }

        if (gethostname(host, sizeof(host))) {
                perror("gethostname()");
                rc = errno;
                goto out_unmap;
	}
        
        rc = mmap_run(host, 3);
        if (rc)
                goto out_unmap;
        
        rc = mmap_wait("mmap done", 10);
        memset(ptr, 'a', region);

        sleep(2);       /* wait for remote test finish */
out_unmap:
        munmap(ptr, region);
out_close:
        close(fd);
        unlink(mmap_file);
        return rc;
}       

static int remote_tst3(char *mnt)
{
        char *ptr, mmap_file[256];
        int region, fd, rc = 0;

        region = page_size * 100;
        sprintf(mmap_file, "%s/%s", mnt, "mmap_file3");

        fd = open(mmap_file, O_RDWR, 0600);
        if (fd < 0) {
                perror(mmap_file);
                return errno;
        }

        ptr = mmap(NULL, region, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED) {
                perror("mmap()");
                rc = errno;
                goto out_close;
        }
        memset(ptr, 'b', region);

        rc = mmap_notify(node, "mmap done", 1);
        if (rc)
                goto out_unmap;
        
        memset(ptr, 'c', region);
        
out_unmap:
        munmap(ptr, region);
out_close:
        close(fd);
        return rc;
}

/* client1 write to file_4a from mmap()ed file_4b;
 * client2 write to file_4b from mmap()ed file_4a. */
static int mmap_tst4(char *mnt)
{
        char *ptr, filea[256], fileb[256], host[256];
        int region, fdr, fdw, rc = 0;

        region = page_size * 100;
        sprintf(filea, "%s/%s", mnt, "mmap_file_4a");
        sprintf(fileb, "%s/%s", mnt, "mmap_file_4b");

        if (unlink(filea) && errno != ENOENT) {
                perror("unlink()");
                return errno;
        }
        if (unlink(fileb) && errno != ENOENT) {
                perror("unlink()");
                return errno;
        }

        fdr = fdw = -1;
        fdr = open(fileb, O_CREAT|O_RDWR, 0600);
        if (fdr < 0) {
                perror(fileb);
                return errno;
        }
        ftruncate(fdr, region);
        fdw = open(filea, O_CREAT|O_RDWR, 0600);
        if (fdw < 0) {
                perror(filea);
                rc = errno;
                goto out_close;
        }
        ftruncate(fdw, region);
        
        ptr = mmap(NULL, region, PROT_READ|PROT_WRITE, MAP_SHARED, fdr, 0);
        if (ptr == MAP_FAILED) {
                perror("mmap()");
                rc = errno;
                goto out_close;
        }

        if (gethostname(host, sizeof(host))) {
                perror("gethostname()");
                rc = errno;
                goto out_unmap;
	}
        
        rc = mmap_run(host, 4);
        if (rc)
                goto out_unmap;
        
        rc = mmap_wait("mmap done", 10);
        if (rc)
                goto out_unmap;
        
        memset(ptr, '1', region);
        
        rc = write(fdw, ptr, region);
        if (rc <= 0) {
                perror("write()");
                rc = errno;
        } else
                rc = 0;

        sleep(2);       /* wait for remote test finish */
out_unmap:
        munmap(ptr, region);
out_close:
        if (fdr >= 0)
                close(fdr);
        if (fdw >= 0)
                close(fdw);
        unlink(filea);
        unlink(fileb);
        return rc;
}

static int remote_tst4(char *mnt)
{
        char *ptr, filea[256], fileb[256];
        int region, fdr, fdw, rc = 0;

        region = page_size * 100;
        sprintf(filea, "%s/%s", mnt, "mmap_file_4a");
        sprintf(fileb, "%s/%s", mnt, "mmap_file_4b");

        fdr = fdw = -1;
        fdr = open(filea, O_RDWR, 0600);
        if (fdr < 0) {
                perror(filea);
                return errno;
        }
        fdw = open(fileb, O_RDWR, 0600);
        if (fdw < 0) {
                perror(fileb);
                rc = errno;
                goto out_close;
        }

        ptr = mmap(NULL, region, PROT_READ|PROT_WRITE, MAP_SHARED, fdr, 0);
        if (ptr == MAP_FAILED) {
                perror("mmap()");
                rc = errno;
                goto out_close;
        }

        rc = mmap_notify(node, "mmap done", 1);
        if (rc)
                goto out_unmap;

        memset(ptr, '2', region);

        rc = write(fdw, ptr, region);
        if (rc <= 0) {
                perror("write()");
                rc = errno;
        } else
                rc = 0;
     
out_unmap:
        munmap(ptr, region);
out_close:
        if (fdr >= 0)
                close(fdr);
        if (fdw >= 0)
                close(fdw);
        return rc;
}

static int remote_tst(int tc, char *mnt)
{
        int rc = 0;
        switch(tc) {
        case 3:
                rc = remote_tst3(mnt);
                break;
        case 4:
                rc = remote_tst4(mnt);
                break;
        case 1:
        case 2:
        default:
                fprintf(stderr, "wrong test case number %d\n", tc);
                rc = EINVAL;
                break;
        }
        return rc;
}
        
struct test_case {
        int     tc;                     /* test case number */
        char    *desc;                  /* test description */
        int     (* test_fn)(char *mnt); /* test function */
        int     node_cnt;               /* node count */
};

struct test_case tests[] = {
        { 1, "mmap test1: basic mmap operation", mmap_tst1, 1 },
        { 2, "mmap test2: MAP_PRIVATE not write back", mmap_tst2, 1 },
        { 3, "mmap test3: cocurrent mmap ops on two nodes", mmap_tst3, 2 },
        { 4, "mmap test4: c1 write to f1 from mmaped f2, " 
             "c2 write to f1 from mmaped f1", mmap_tst4, 2 },
        { 0, NULL, 0, 0 }
};

int main(int argc, char **argv)
{
        extern char *optarg;
        struct test_case *test;
        int c, rc = 0, tc = 0;

        for(;;) {
                c = getopt(argc, argv, "d:n:c:m:");
                if ( c == -1 )
                        break;

                switch(c) {
                        case 'd':
                                dir = optarg;
                                break;
                        case 'n':
                                node = optarg;
                                break;
                        case 'c':
                                tc = atoi(optarg);
                                break;
                        case 'm':
                                dir2 = optarg;
                                break;
                        default:
                        case '?':
                                usage();
                                break;
                }
        }

        if (dir == NULL)
                usage();
        if (dir2 != NULL && node != NULL)
                usage();

        if (mmap_initialize(argv[0], tc) != 0) {
                fprintf(stderr, "mmap_initialize failed!\n");
                return EINVAL;
        }

        if (tc) {
                rc = remote_tst(tc, dir);
                goto out;
        }
        
        for (test = tests; test->tc; test++) {
                char *rs = "skip";
                rc = 0;
                if (test->node_cnt == 1 || node != NULL || dir2 != NULL) {
                        rc = test->test_fn(dir);
                        rs = rc ? "fail" : "pass";
                }
                fprintf(stderr, "%s (%s)\n", test->desc, rs);
                if (rc)
                        break;
        }
out:
        mmap_finalize(tc);
        return rc;
}
