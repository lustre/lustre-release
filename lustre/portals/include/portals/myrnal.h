#ifndef MYRNAL_H
#define MYRNAL_H

#define MAX_ARGS_LEN            (256)
#define MAX_RET_LEN             (128)
#define MYRNAL_MAX_ACL_SIZE     (64)
#define MYRNAL_MAX_PTL_SIZE     (64)

#define P3CMD                   (100)
#define P3SYSCALL               (200)
#define P3REGISTER              (300)

enum { PTL_MLOCKALL };

typedef struct {
	void *args;
	size_t args_len;
	void *ret;
	size_t ret_len;
	int p3cmd;
} myrnal_forward_t;

#endif				/* MYRNAL_H */
