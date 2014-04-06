#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int rc;
	int fd = open(argv[1], O_WRONLY);

	if (fd == -1) {
		perror(argv[1]);
		goto read;
	}

	/* We need rc because Sles11 compiler warns against unchecked
	 * return value of read and write */
	rc = write(fd, (void *)0x4096000, 5);
	if (rc != 5)
		perror("write badarea (Should have failed)");

	rc = write(fd, &fd, 0);
	if (rc != 0)
		perror("write zero bytes");

	rc = write(fd, &fd, 1);
	if (rc != 1)
		perror("write one byte");

	rc = write(fd, &fd, 2UL*1024*1024);
	if (rc != 2UL*1024*1024)
		perror("write 2M");

	rc = write(fd, &fd, 2UL*1024*1024*1024);
	if (rc != 2UL*1024*1024*1024)
		perror("write 2G");

	rc = write(fd, &fd, -2);
	if (rc != -2)
		perror("write -2");

	close(fd);

read:
	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
		return 0;
	rc = read(fd, (void *)0x4096000, 5);
	perror("read");

	close(fd);

	/* Tame the compiler spooked about rc assigned, but not used */
	if (!rc)
		return -1; /* Not really important. */

	return 0;
}
