int  fsfilt_ext3_init(void);
void fsfilt_ext3_exit(void);

int  fsfilt_extN_init(void);
void fsfilt_extN_exit(void);

int  fsfilt_ldiskfs_init(void);
void fsfilt_ldiskfs_exit(void);

int  fsfilt_reiser_init(void);
void fsfilt_reiser_exit(void);

void lvfs_mount_list_init(void);
void lvfs_mount_list_cleanup(void);

int lookup_by_path(char *path, int flags, struct nameidata *nd);

