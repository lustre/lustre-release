#ifndef _IOWR

/* On i386 and x86_64, _ASM_I386_IOCTL_H is defined by the kernel's ioctl.h,
 * and on newer kernels this header is shared as _ASM_GENERIC_IOCTL_H.
 *
 * We can avoid any problems with the kernel header being included again by
 * defining _ASM_I386_IOCTL_H here so that a later occurence of <asm/ioctl.h>
 * does not include the kernel's ioctl.h after this one. b=14746 */
#define _ASM_I386_IOCTL_H
#define _ASM_GENERIC_IOCTL_H

/* ioctl command encoding: 32 bits total, command in lower 16 bits,
 * size of the parameter structure in the lower 14 bits of the
 * upper 16 bits.
 * Encoding the size of the parameter structure in the ioctl request
 * The highest 2 bits are reserved for indicating the ``access mode''.
 * NOTE: This limits the max parameter size to 16kB -1 !
 */

/*
 * The following is for compatibility across the various Linux
 * platforms.  The i386 ioctl numbering scheme doesn't really enforce
 * a type field.  De facto, however, the top 8 bits of the lower 16
 * bits are indeed used as a type field, so we might just as well make
 * this explicit here.  Please be sure to use the decoding macros
 * below from now on.
 */
#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8
#define _IOC_SIZEBITS   14
#define _IOC_DIRBITS    2

#define _IOC_NRMASK     ((1 << _IOC_NRBITS)-1)
#define _IOC_TYPEMASK   ((1 << _IOC_TYPEBITS)-1)
#define _IOC_SIZEMASK   ((1 << _IOC_SIZEBITS)-1)
#define _IOC_DIRMASK    ((1 << _IOC_DIRBITS)-1)

#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT+_IOC_SIZEBITS)

/*
 * Direction bits.
 */
#define _IOC_NONE       0U
#define _IOC_WRITE      1U
#define _IOC_READ       2U

#define _IOC(dir,type,nr,size) (((dir)  << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | ((nr)   << _IOC_NRSHIFT) | ((size) << _IOC_SIZESHIFT))

/* used to create numbers */
#define _IO(type,nr)            _IOC(_IOC_NONE,(type),(nr),0)
#define _IOR(type,nr,size)      _IOC(_IOC_READ,(type),(nr),sizeof(size))
#define _IOW(type,nr,size)      _IOC(_IOC_WRITE,(type),(nr),sizeof(size))
#define _IOWR(type,nr,size)     _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))

/* used to decode ioctl numbers.. */
#define _IOC_DIR(nr)            (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr)           (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr)             (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr)           (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

/* ...and for the drivers/sound files... */

#define IOC_IN          (_IOC_WRITE << _IOC_DIRSHIFT)
#define IOC_OUT         (_IOC_READ << _IOC_DIRSHIFT)
#define IOC_INOUT       ((_IOC_WRITE|_IOC_READ) << _IOC_DIRSHIFT)
#define IOCSIZE_MASK    (_IOC_SIZEMASK << _IOC_SIZESHIFT)
#define IOCSIZE_SHIFT   (_IOC_SIZESHIFT)

#endif /* _IOWR */

