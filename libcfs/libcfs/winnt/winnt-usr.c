
#ifndef __KERNEL__

#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <time.h>
#include <windows.h>

void portals_debug_msg(int subsys, int mask, char *file, const char *fn,
                              const int line, unsigned long stack,
                              char *format, ...) {
    }

int cfs_proc_mknod(const char *path, unsigned short  mode,  unsigned int dev)
{
    return 0;
}


void print_last_error(char* Prefix)
{
    LPVOID lpMsgBuf;

    FormatMessage( 
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        0,
        (LPTSTR) &lpMsgBuf,
        0,
        NULL
        );

    printf("%s %s", Prefix, (LPTSTR) lpMsgBuf);

    LocalFree(lpMsgBuf);
}

//
// The following declarations are defined in io.h of VC
// sys/types.h will conflict with io.h, so we need place
// these declartions here.

#ifdef __cplusplus
extern "C" {
#endif
    void
    __declspec (naked) __cdecl _chkesp(void)
    {
#if _X86_
        __asm {  jz      exit_chkesp     };
        __asm {  int     3               };
    exit_chkesp:
        __asm {  ret                     };
#endif
    }
#ifdef __cplusplus
}
#endif

unsigned int sleep (unsigned int seconds)
{
    Sleep(seconds * 1000);
    return 0;
}

int gethostname(char * name, int namelen)
{
    return 0;
}

int ioctl (
    int handle,
    int cmd,
    void *buffer
    )
{
    printf("hello, world\n");
    return 0;
}

#endif /* __KERNEL__ */