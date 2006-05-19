/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * (visit-tags-table FILE)
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _DARWIN_LUSTRE_DLM_H__
#define _DARWIN_LUSTRE_DLM_H__

#ifndef _LUSTRE_DLM_H__
#error Do not #include this file directly. #include <lprocfs_status.h> instead
#endif

#define IT_OPEN     0x0001
#define IT_CREAT    0x0002
#define IT_READDIR  0x0004
#define IT_GETATTR  0x0008
#define IT_LOOKUP   0x0010
#define IT_UNLINK   0x0020
#define IT_GETXATTR 0x0040
#define IT_EXEC     0x0080
#define IT_PIN      0x0100
#define IT_CHDIR    0x0200


#endif
