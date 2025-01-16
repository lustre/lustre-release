/* SPDX-License-Identifier: GPL-2.0 */

#ifndef LLITE_FOREIGN_SYMLINK_H
#define LLITE_FOREIGN_SYMLINK_H

/* llite/llite_foreign_symlink.c */
ssize_t foreign_symlink_enable_show(struct kobject *kobj,
				    struct attribute *attr, char *buf);
ssize_t foreign_symlink_enable_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count);
ssize_t foreign_symlink_prefix_show(struct kobject *kobj,
				    struct attribute *attr, char *buf);
ssize_t foreign_symlink_prefix_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count);
ssize_t foreign_symlink_upcall_show(struct kobject *kobj,
				    struct attribute *attr, char *buf);
ssize_t foreign_symlink_upcall_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count);
ssize_t foreign_symlink_upcall_info_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count);
extern struct inode_operations ll_foreign_file_symlink_inode_operations;
extern struct inode_operations ll_foreign_dir_symlink_inode_operations;

#endif /* LLITE_FOREIGN_SYMLINK_H */
