/*
 * smfs/kml_idl.h
 */

# define MYPATHLEN(buffer, path) ((buffer) + PAGE_SIZE - (path))
/*Got these defines from intermezzo*/
struct kml_log_fd {
	rwlock_t         fd_lock;
        loff_t           fd_offset;  /* offset where next record should go */
        struct file      *fd_file;
        int              fd_truncating;
        unsigned int     fd_recno;   /* last recno written */
        struct list_head fd_reservations;
};

#define KML_MAJOR_VERSION 0x00010000
#define KML_MINOR_VERSION 0x00000002
#define KML_OPCODE_NOOP          0
#define KML_OPCODE_CREATE        1
#define KML_OPCODE_MKDIR         2
#define KML_OPCODE_UNLINK        3
#define KML_OPCODE_RMDIR         4
#define KML_OPCODE_CLOSE         5
#define KML_OPCODE_SYMLINK       6
#define KML_OPCODE_RENAME        7
#define KML_OPCODE_SETATTR       8
#define KML_OPCODE_LINK          9
#define KML_OPCODE_OPEN          10
#define KML_OPCODE_MKNOD         11
#define KML_OPCODE_WRITE         12
#define KML_OPCODE_RELEASE       13
#define KML_OPCODE_TRUNC         14
#define KML_OPCODE_SETEXTATTR    15
#define KML_OPCODE_DELEXTATTR    16
#define KML_OPCODE_KML_TRUNC     17
#define KML_OPCODE_GET_FILEID    18
#define KML_OPCODE_NUM           19
                                                                                                                                                                                                     
#ifdef __KERNEL__
# define NTOH__u32(var) le32_to_cpu(var)
# define NTOH__u64(var) le64_to_cpu(var)
# define HTON__u32(var) cpu_to_le32(var)
# define HTON__u64(var) cpu_to_le64(var)
#else
# include <glib.h>
# define NTOH__u32(var) GUINT32_FROM_LE(var)
# define NTOH__u64(var) GUINT64_FROM_LE(var)
# define HTON__u32(var) GUINT32_TO_LE(var)
# define HTON__u64(var) GUINT64_TO_LE(var)
#endif
                                                                                                                                                                                                     

