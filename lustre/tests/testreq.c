#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define IOC_REQUEST_GETATTR		_IOWR('f', 30, long)
#define IOC_REQUEST_READPAGE		_IOWR('f', 31, long)
#define IOC_REQUEST_SETATTR		_IOWR('f', 32, long)
#define IOC_REQUEST_CREATE		_IOWR('f', 33, long)

int main(int argc, char **argv)
{
	int fd, rc; 
	int cmd = IOC_REQUEST_GETATTR;

	printf("ioctl type %d, nr %d size %d\n", 
	       _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));

	fd = open("/dev/request", O_RDONLY);
	if (fd == -1) { 
		printf("error opening /dev/request: %s\n", strerror(errno));
		return 1;
	}

	printf("getattr test... ");
	rc = ioctl(fd, IOC_REQUEST_GETATTR, NULL); 
	printf("result: %d\n", rc); 

	printf("readpage test... ");
	rc = ioctl(fd, IOC_REQUEST_READPAGE, NULL); 
	printf("result: %d\n", rc); 

	printf("setattr test... ");
	rc = ioctl(fd, IOC_REQUEST_SETATTR, NULL); 
	printf("result: %d\n", rc); 

	printf("create test... ");
	rc = ioctl(fd, IOC_REQUEST_CREATE, NULL); 
	printf("result: %d\n", rc); 
	return 0;
}
