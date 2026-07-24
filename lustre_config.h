/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* BDI_CAP_CGROUP_WRITEBACK is missing */
#define BDI_CAP_CGROUP_WRITEBACK 0

/* enable libcfs CDEBUG, CWARN */
#define CDEBUG_ENABLED 1

/* enable libcfs ENTRY/EXIT */
#define CDEBUG_ENTRY_EXIT 1

/* enable page state tracking code */
/* #undef CONFIG_DEBUG_PAGESTATE_TRACKING */

/* enable encryption for ldiskfs */
/* #undef CONFIG_LDISKFS_FS_ENCRYPTION */

/* posix acls for ldiskfs */
/* #undef CONFIG_LDISKFS_FS_POSIX_ACL */

/* enable rw access for ldiskfs */
/* #undef CONFIG_LDISKFS_FS_RW */

/* fs security for ldiskfs */
/* #undef CONFIG_LDISKFS_FS_SECURITY */

/* extened attributes for ldiskfs */
/* #undef CONFIG_LDISKFS_FS_XATTR */

/* Enable Lustre client crypto via embedded llcrypt */

/* use dumplog on panic */
/* #undef CONFIG_LNET_DUMP_ON_PANIC */

/* enable invariant checking */
/* #undef CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK */

/* Use the Pinger */
#define CONFIG_LUSTRE_FS_PINGER 1

/* Enable POSIX acl */
#define CONFIG_LUSTRE_FS_POSIX_ACL 1

/* build lustre server kernel support */
#define CONFIG_LUSTRE_FS_SERVER 1

/* MODULE_IMPORT_NS() needs string literal */
#define CRYPTO_INTERNAL __stringify(CRYPTO_INTERNAL)

/* fl_file exists */
#define C_FLC_FILE c.flc_file

/* fl_flags exists */
#define C_FLC_FLAGS c.flc_flags

/* fl_owner exists */
#define C_FLC_OWNER c.flc_owner

/* fl_pid exists */
#define C_FLC_PID c.flc_pid

/* c.flc_type is missing */
#define C_FLC_TYPE c.flc_type

/* 'ClearPageError()' replacement */
#define ClearPageError(pg) /**/

/* name of ldiskfs debug program */
#define DEBUGFS "debugfs"

/* d_u union needed to access d_alias */
#define DENTRY_D_ALIAS d_alias

/* DMU_TX_WAIT does not exist as define or enum */
/* #undef DMU_TX_WAIT */

/* name of ldiskfs dump program */
#define DUMPE2FS "dumpe2fs"

/* name of ldiskfs fsck program */
#define E2FSCK "e2fsck"

/* name of ldiskfs e2fsprogs package */
#define E2FSPROGS "e2fsprogs"

/* name of ldiskfs label program */
#define E2LABEL "e2label"

/* filldir_t return type is bool or int */
#define FILLDIR_TYPE bool

/* folio_memcg_{,un}lock are exported */
/* #undef FOLIO_MEMCG_LOCK_EXPORTED */

/* struct genl_family has resv_start_op member */
#define GENL_FAMILY_HAS_RESV_START_OP 1

/* account_page_dirtied() is defined */
/* #undef HAVE_ACCOUNT_PAGE_DIRTIED */

/* account_page_dirtied is exported */
/* #undef HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT */

/* 'get_acl' and 'set_acl' use dentry argument */
#define HAVE_ACL_WITH_DENTRY 1

/* add_to_page_cache_locked is exported by the kernel */
/* #undef HAVE_ADD_TO_PAGE_CACHE_LOCKED */

/* aes-sha2 is supported by krb5 */
/* #undef HAVE_AES_SHA2_SUPPORT */

/* alloc_inode_sb() exists */
#define HAVE_ALLOC_INODE_SB 1

/* struct address_space_operations() has migrate_folio() */
#define HAVE_AOPS_MIGRATE_FOLIO 1

/* struct address_space_operations() has read_folio() */
#define HAVE_AOPS_READ_FOLIO 1

/* struct address_space_operations() has release_folio() */
#define HAVE_AOPS_RELEASE_FOLIO 1

/* Define to 1 if you have the <asm/types.h> header file. */
#define HAVE_ASM_TYPES_H 1

/* backing_dev_info has debug_stats */
/* #undef HAVE_BDI_DEBUG_STATS */

/* 'bio_add_folio()' is available */
/* #undef HAVE_BIO_ADD_FOLIO */

/* bio_alloc() takes a struct block_device */
#define HAVE_BIO_ALLOC_WITH_BDEV 1

/* struct bio has bi_phys_segments member */
/* #undef HAVE_BIO_BI_PHYS_SEGMENTS */

/* 'bio_set_dev' is available */
#define HAVE_BIO_SET_DEV 1

/* 'bi_bdev' is available */
#define HAVE_BI_BDEV 1

/* BLK_INTEGRITY_NOVERIFY is available */
#define HAVE_BLK_INTEGRITY_NOVERIFY 1

/* if bvec_iter_all exists for multi-page bvec iteration */
#define HAVE_BVEC_ITER_ALL 1

/* struct cache_detail has writers */
#define HAVE_CACHE_DETAIL_WRITERS 1

/* crypto/internal/cipher.h is present */
#define HAVE_CIPHER_H 1

/* 'class_create' does not have module arg */
#define HAVE_CLASS_CREATE_NO_ARG 1

/* copy_file_range() is supported */
#define HAVE_COPY_FILE_RANGE 1

/* 'copy_folio_from_iter_atomic' exists */
#define HAVE_COPY_FOLIO_FROM_ITER_ATOMIC 1

/* 'copy_page_from_iter_atomic' exists */
/* #undef HAVE_COPY_PAGE_FROM_ITER_ATOMIC */

/* crypto/sha2.h is present */
#define HAVE_CRYPTO_SHA2_HEADER 1

/* struct blk_integrity has csum_type field */
#define HAVE_CSUM_TYPE_BLK_INTEGRITY 1

/* debugfs_lookup_and_remove() is available */
#define HAVE_DEBUGFS_LOOKUP_AND_REMOVE 1

/* delete_from_page_cache is exported */
/* #undef HAVE_DELETE_FROM_PAGE_CACHE */

/* struct dentry has d_children member */
#define HAVE_DENTRY_D_CHILDREN 1

/* dentry->__d_name exists */
#define HAVE_DENTRY__D_NAME 1

/* address_spaace_operaions->dirty_folio() member exists */
#define HAVE_DIRTY_FOLIO 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Have dmu_assign_arcbuf_by_dbuf() does not have flags */
/* #undef HAVE_DMU_ASSIGN_ARCBUF_BY_DBUF_WITHOUT_FLAGS */

/* Have dmu_assign_arcbuf_by_dbuf() with flags */
#define HAVE_DMU_ASSIGN_ARCBUF_BY_DBUF_WITH_FLAGS 1

/* dmu_buf_will_fill() has 3 args */
#define HAVE_DMU_BUF_WILL_FILL_3ARGS 1

/* dmu_buf_hold_array_by_bonus has flags */
#define HAVE_DMU_HOLD_ARRAY_BY_BONUS_FLAGS 1

/* dmu_buf_hold_array_by_bonus has no flags */
/* #undef HAVE_DMU_HOLD_ARRAY_BY_BONUS_NOFLAGS */

/* Have dmu_offset_next() exported */
#define HAVE_DMU_OFFSET_NEXT 1

/* DMU_TX_WAIT exists and define or enum */
#define HAVE_DMU_TX_WAIT 1

/* Have dmu_write_by_dnode without flags arg */
/* #undef HAVE_DMU_WRITE_BY_DNODE_WITHOUT_FLAGS */

/* Have dmu_write_by_dnode() with flags in ZFS */
#define HAVE_DMU_WRITE_BY_DNODE_WITH_FLAGS_ARG 1

/* use mnt_idmap with dquot_transfer */
#define HAVE_DQUOT_TRANSFER_WITH_USER_NS 1

/* Have dsl_pool_config_enter/exit in ZFS */
#define HAVE_DSL_POOL_CONFIG 1

/* d_exchange is exported */
#define HAVE_D_EXCHANGE_EXPORT 1

/* d_make_persistent() exists */
#define HAVE_D_MAKE_PERSISTENT 1

/* dentry operations d_revalidate() takes inode, name */
#define HAVE_D_REVALIDATE_WITH_INODE_NAME 1

/* ib_dma_pci_p2p_dma_supported() is defined */
/* #undef HAVE_EFA_IB_DMA_PCI_P2P_DMA_SUPPORTED */

/* Define to 1 if you have the <endian.h> header file. */
#define HAVE_ENDIAN_H 1

/* enum iter_type has member 'iter_pipe' */
/* #undef HAVE_ENUM_ITER_PIPE */

/* ext4_bread takes 4 arguments */
#define HAVE_EXT4_BREAD_4ARGS 1

/* ext4_(inc|dec)_count() has 2 arguments */
/* #undef HAVE_EXT4_INC_DEC_COUNT_2ARGS */

/* i_dquot is in ext4_inode_info */
#define HAVE_EXT4_INFO_DQUOT 1

/* ext4_journal_get_create_access() has 4 arguments */
/* #undef HAVE_EXT4_JOURNAL_GET_CREATE_ACCESS_4ARGS */

/* ext4_journal_get_write_access() has 4 arguments */
/* #undef HAVE_EXT4_JOURNAL_GET_WRITE_ACCESS_4ARGS */

/* 'fault_in_iov_iter_readable' exists */
#define HAVE_FAULT_IN_IOV_ITER_READABLE 1

/* file handle and related syscalls are supported */
#define HAVE_FHANDLE_GLIBC_SUPPORT 1

/* union is unnamed */
/* #undef HAVE_FID2PATH_ANON_UNIONS */

/* 'inode_operations' has fileattr_get and fileattr_set */
#define HAVE_FILEATTR_GET 1

/* filemap_alloc_folio() takes NUMA mempolicy */
#define HAVE_FILEMAP_ALLOC_FOLIO_NUMA 1

/* filemap_get_folios() exists */
#define HAVE_FILEMAP_GET_FOLIOS 1

/* filemap_get_folios_contig() is available */
#define HAVE_FILEMAP_GET_FOLIOS_CONTIG 1

/* 'filemap_splice_read' is exported */
#define HAVE_FILEMAP_SPLICE_READ 1

/* struct file_kattr exists */
#define HAVE_FILE_KATTR 1

/* file->__f_path exists */
#define HAVE_FILE__F_PATH 1

/* filldir_t needs struct dir_context and returns bool */
#define HAVE_FILLDIR_USE_CTX_RETURN_BOOL 1

/* flush_delayed_fput() is exported by the kernel */
#define HAVE_FLUSH_DELAYED_FPUT 1

/* '__flush_workqueue(system_wq)' is available */
#define HAVE_FLUSH___WORKQUEUE 1

/* 'struct folio_batch' is available */
#define HAVE_FOLIO_BATCH 1

/* 'folio_batch_reinit' is available */
#define HAVE_FOLIO_BATCH_REINIT 1

/* 'folio_mapcount()' is available */
#define HAVE_FOLIO_MAPCOUNT 1

/* folio_memcg_lock is defined */
/* #undef HAVE_FOLIO_MEMCG_LOCK */

/* folio_memcg_lock() is static inline */
#define HAVE_FOLIO_MEMCG_LOCK_STATIC 1

/* 'struct fscrypt_digested_name' exists */
/* #undef HAVE_FSCRYPT_DIGESTED_NAME */

/* embedded llcrypt uses llcrypt_dummy_context_enabled() */
/* #undef HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED */

/* fscrypt_free_dummy_policy() exists */
#define HAVE_FSCRYPT_DUMMY_POLICY 1

/* fscrypt_d_revalidate() is exported by the kernel */
#define HAVE_FSCRYPT_D_REVALIDATE 1

/* fscrypt_fname_alloc_buffer() does not have inode parameter */
#define HAVE_FSCRYPT_FNAME_ALLOC_BUFFER_NO_INODE 1

/* fscrypt_is_nokey_name() exists */
#define HAVE_FSCRYPT_IS_NOKEY_NAME 1

/* struct fscrypt_name has is_nokey_name field */
#define HAVE_FSCRYPT_NOKEY_NAME 1

/* fscrypt_prepare_readdir() exists */
#define HAVE_FSCRYPT_PREPARE_READDIR 1

/* fscrypt_set_context() does exist */
#define HAVE_FSCRYPT_SET_CONTEXT 1

/* fscrypt_set_test_dummy_encryption() take 'const char' parameter */
/* #undef HAVE_FSCRYPT_SET_TEST_DUMMY_ENC_CHAR_ARG */

/* generic_error_remove_folio() exists */
#define HAVE_GENERIC_ERROR_REMOVE_FOLIO 1

/* 'generic_fillattr()' has request_mask argument */
#define HAVE_GENERIC_FILEATTR_HAS_MASK_ARG 1

/* struct genl_dumpit_info has family field */
/* #undef HAVE_GENL_DUMPIT_INFO_FAMILY */

/* 'get_acl' has a rcu argument */
/* #undef HAVE_GET_ACL_RCU_ARG */

/* get_random_[u32|u64] are available */
#define HAVE_GET_RANDOM_U32_AND_U64 1

/* get_random_u32_below() is available */
#define HAVE_GET_RANDOM_U32_BELOW 1

/* get_user_pages removed 'vma' parameter */
#define HAVE_GET_USER_PAGES_WITHOUT_VMA 1

/* support gemini LND */
/* #undef HAVE_GNILND */

/* grab_cache_page_write_begin() is available */
/* #undef HAVE_GRAB_CACHE_PAGE_WRITE_BEGIN */

/* grab_cache_page_write_begin() has flags argument */
/* #undef HAVE_GRAB_CACHE_PAGE_WRITE_BEGIN_WITH_FLAGS */

/* 'struct group_info.usage' is refcount_t */
#define HAVE_GROUP_INFO_USAGE_AS_REFCOUNT 1

/* Define this is if you enable gss */
/* #undef HAVE_GSS */

/* Define this if you enable gss keyring backend */
/* #undef HAVE_GSS_KEYRING */

/* Define this if the Kerberos GSS library supports gss_krb5_ccache_name */
/* #undef HAVE_GSS_KRB5_CCACHE_NAME */

/* Define this if you have Heimdal Kerberos libraries */
/* #undef HAVE_HEIMDAL */

/* hrtimer_setup() is available */
#define HAVE_HRTIMER_SETUP 1

/* ibdev_to_node() is defined */
/* #undef HAVE_IBDEV_TO_NODE */

/* (external) 'IBK_SG_GAPS_REG' exists */
/* #undef HAVE_IBK_SG_GAPS_REG */

/* ilookup5_nowait() takes isnew */
#define HAVE_ILOOKUP5_NOWAIT_ISNEW 1

/* 'inode_get_ctime()' exists */
#define HAVE_INODE_GET_CTIME 1

/* 'inode_get_mtime()' exists */
#define HAVE_INODE_GET_MTIME_SEC 1

/* inode_just_drop() exists */
#define HAVE_INODE_JUST_DROP 1

/* inode_lock_shared() defined */
/* #undef HAVE_INODE_LOCK_SHARED */

/* inode_state_read() exists */
#define HAVE_INODE_STATE_READ 1

/* ib_client add() returns int */
#define HAVE_INT_IB_CLIENT_ADD 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* address_spaace_operaions->invalidate_folio() member exists */
#define HAVE_INVALIDATE_FOLIO 1

/* filemap_invalidate_lock() is available */
#define HAVE_INVALIDATE_LOCK 1

/* 'in_dev_for_each_ifa_rtnl' is defined */
#define HAVE_IN_DEV_FOR_EACH_IFA_RTNL 1

/* inode_operations.create() has no excl arg */
#define HAVE_IOPS_CREATE_NO_EXCL 1

/* inode_operations.mkdir() returns dentry */
#define HAVE_IOPS_MKDIR_RETURNS_DENTRY 1

/* inode_operations has .get_inode_acl member function */
#define HAVE_IOP_GET_INODE_ACL 1

/* iov_iter_extract_pages() is available */
#define HAVE_IOV_ITER_EXTRACT_PAGES 1

/* iov_iter_get_pages_alloc2() is available */
#define HAVE_IOV_ITER_GET_PAGES_ALLOC2 1

/* 'iov_iter_iovec' is available */
/* #undef HAVE_IOV_ITER_IOVEC */

/* if ip6_sock_set_addr_preferences exists */
#define HAVE_IP6_SET_PREF 1

/* if ip_sock_set_tos exists */
#define HAVE_IP_SET_TOS 1

/* is_pci_p2pdma_page exists */
#define HAVE_IS_PCI_P2PDMA_PAGE 1

/* 'iter_file_splice_write' exists */
#define HAVE_ITER_FILE_SPLICE_WRITE 1

/* iter_iov() is available */
#define HAVE_ITER_IOV 1

/* 'i_user_ns' helper exists */
#define HAVE_I_USER_NS 1

/* if jbd2_journal_get_max_txn_bufs is available */
/* #undef HAVE_JBD2_JOURNAL_GET_MAX_TXN_BUFS */

/* struct jbd2_journal_handle has h_total_credits member */
#define HAVE_JOURNAL_TOTAL_CREDITS 1

/* kallsyms_lookup_name is exported by kernel */
/* #undef HAVE_KALLSYMS_LOOKUP_NAME */

/* kernel_setsockopt still in use */
/* #undef HAVE_KERNEL_SETSOCKOPT */

/* keyring_search has 4 args */
#define HAVE_KEYRING_SEARCH_4ARGS 1

/* KEY_NEED_UNLINK exists */
#define HAVE_KEY_NEED_UNLINK 1

/* support kfabric LND */
#define HAVE_KFILND 1

/* kfi_cxi domain ops are available */
/* #undef HAVE_KFI_CXI_DOM_OPS */

/* KFI_SGL IOV type is supported */
/* #undef HAVE_KFI_SGL */

/* kfree_sensitive() is available. */
#define HAVE_KFREE_SENSITIVE 1

/* kill_litter_super() exists */
/* #undef HAVE_KILL_LITTER_SUPER */

/* kiocb->ki_complete() has 2 arguments */
#define HAVE_KIOCB_COMPLETE_2ARGS 1

/* kmap_local_* functions are available */
#define HAVE_KMAP_LOCAL 1

/* struct kobj_type has 'default_groups' member */
#define HAVE_KOBJ_TYPE_DEFAULT_GROUPS 1

/* Define this if you have MIT Kerberos libraries */
/* #undef HAVE_KRB5 */

/* Define this if the function krb5int_derive_key is available */
/* #undef HAVE_KRB5INT_DERIVE_KEY */

/* Define this if the function krb5_derive_key is available */
/* #undef HAVE_KRB5_DERIVE_KEY */

/* Define this if the function krb5_get_error_message is available */
/* #undef HAVE_KRB5_GET_ERROR_MESSAGE */

/* Define this if the function krb5_get_init_creds_opt_set_addressless is
   available */
/* #undef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_ADDRESSLESS */

/* 'kthread_use_mm' exists */
#define HAVE_KTHREAD_USE_MM 1

/* 'kvfree_atomic()' is exported */
#define HAVE_KVFREE_ATOMIC_EXPORTED 1

/* lbug_with_loc is in objtool global_noreturns array */
/* #undef HAVE_LBUG_WITH_LOC_IN_OBJTOOL */

/* if ldiskfsfs_dirhash takes an inode argument */
#define HAVE_LDISKFSFS_DIRHASH_WITH_DIR 1

/* enable use of ldiskfsprogs package */
/* #undef HAVE_LDISKFSPROGS */

/* 'EXT4_IGET_EA_INODE' exists */
#define HAVE_LDISKFS_IGET_EA_INODE 1

/* if ldiskfs_iget takes a flags argument */
#define HAVE_LDISKFS_IGET_WITH_FLAGS 1

/* 'ext4_journal_ensure_credits' exists */
#define HAVE_LDISKFS_JOURNAL_ENSURE_CREDITS 1

/* Enable ldiskfs osd */
/* #undef HAVE_LDISKFS_OSD */

/* libefence support is requested */
/* #undef HAVE_LIBEFENCE */

/* Define to 1 if you have the 'keyutils' library (-lkeyutils). */
#define HAVE_LIBKEYUTILS 1

/* use libpthread for libcfs library */
#define HAVE_LIBPTHREAD 1

/* readline library is available */
#define HAVE_LIBREADLINE 1

/* linux/bio-integrity.h is present */
#define HAVE_LINUX_BIO_INTEGRITY_HEADER 1

/* linux/blk-integrity.h is present */
#define HAVE_LINUX_BLK_INTEGRITY_HEADER 1

/* linux/filelock.h is present */
#define HAVE_LINUX_FILELOCK_HEADER 1

/* linux/fortify-string.h header available */
#define HAVE_LINUX_FORTIFY_STRING_HEADER 1

/* linux/stdarg.h is present */
#define HAVE_LINUX_STDARG_HEADER 1

/* linux/unaligned.h header is available */
#define HAVE_LINUX_UNALIGNED_HEADER 1

/* list_cmp_func_t type is defined */
#define HAVE_LIST_CMP_FUNC_T 1

/* lock_manager_operations has lm_compare_owner */
/* #undef HAVE_LM_COMPARE_OWNER */

/* lock_manager_operations.lm_grant takes two args */
#define HAVE_LM_GRANT_2ARGS 1

/* kernel has locks_lock_file_wait in filelock.h */
#define HAVE_LOCKS_LOCK_FILE_WAIT 1

/* lsm_context has id */
#define HAVE_LSMCONTEXT_HAS_ID 1

/* lsmcontext_init is available */
/* #undef HAVE_LSMCONTEXT_INIT */

/* Enable Lustre client crypto */

/* 'mapped_fsuid' and <linux/mnt_idmapping.h> exist */
#define HAVE_MAPPED_FSUID 1

/* page->flags is struct */
#define HAVE_MEMDESC_FLAGS_T 1

/* mmap_lock API is available. */
#define HAVE_MMAP_LOCK 1

/* 'mmap_write_trylock()' is available */
/* #undef HAVE_MMAP_WRITE_TRYLOCK */

/* 'inode_operations' members have mnt_idmap argument */
#define HAVE_MNT_IDMAP_ARG 1

/* MODULE_IMPORT_NS() needs string literal */
/* #undef HAVE_MODULE_IMPORT_USES_EXPORT_SYMBOLS */

/* kernel module loading is possible */
#define HAVE_MODULE_LOADING_SUPPORT 1

/* Define to 1 if you have the 'name_to_handle_at' function. */
#define HAVE_NAME_TO_HANDLE_AT 1

/* support native Linux client */
/* #undef HAVE_NATIVE_LINUX_CLIENT */

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* 'netdev_lock_ops' is present */
#define HAVE_NETDEV_LOCK_OPS 1

/* netif_get_flags exists */
#define HAVE_NETIF_GET_FLAGS 1

/* libnl3 supports nla_get_s32 */
#define HAVE_NLA_GET_S32 1

/* libnl3 supports nla_get_s64 */
#define HAVE_NLA_GET_S64 1

/* 'nla_strlcpy' is available */
/* #undef HAVE_NLA_STRLCPY */

/* no_llseek() is available */
/* #undef HAVE_NO_LLSEEK */

/* NR_UNSTABLE_NFS is still in use. */
/* #undef HAVE_NR_UNSTABLE_NFS */

/* NR_UNSTABLE_NFS is defined but deprecated */
/* #undef HAVE_NR_UNSTABLE_NFS_DEPRECATED */

/* 'struct nsproxy.count' is refcount_t */
#define HAVE_NSPROXY_COUNT_AS_REFCOUNT 1

/* compat rdma found */
/* #undef HAVE_OFED_COMPAT_RDMA */

/* (external) FMR pools API available */
/* #undef HAVE_OFED_FMR_POOL_API */

/* (external) struct ib_device_ops is defined */
/* #undef HAVE_OFED_IB_DEVICE_OPS */

/* (external) if ib_dma_map_sg() is sane */
/* #undef HAVE_OFED_IB_DMA_MAP_SG_SANE */

/* (external) ib_dma_pci_p2p_dma_supported exists */
/* #undef HAVE_OFED_IB_DMA_PCI_P2P_DMA_SUPPORTED */

/* (external) ib_sg_dma_address wrapper exists */
/* #undef HAVE_OFED_IB_SG_DMA_ADDRESS */

/* (external) 'rdma_connect_locked' exists */
/* #undef HAVE_OFED_RDMA_CONNECT_LOCKED */

/* (external) 4arg 'rdma_reject' exists */
/* #undef HAVE_OFED_RDMA_REJECT_4ARGS */

/* OpenSSL EVP_PKEY_get_params */
#define HAVE_OPENSSL_EVP_PKEY 1

/* OpenSSL FIPS_mode */
/* #undef HAVE_OPENSSL_FIPS */

/* openssl-devel is present */
#define HAVE_OPENSSL_GETSEPOL 1

/* OpenSSL HMAC functions needed for SSK */
#define HAVE_OPENSSL_SSK 1

/* struct p2pdma_provider exists */
#define HAVE_P2PDMA_PROVIDER 1

/* 'struct pagevec' is available */
#define HAVE_PAGEVEC 1

/* page_pgmap() exists */
#define HAVE_PAGE_PGMAP 1

/* PagePrivate2() is available */
/* #undef HAVE_PAGE_PRIVATE_2 */

/* linux/panic_notifier.h is present */
#define HAVE_PANIC_NOTIFIER_H 1

/* 'param_set_uint_minmax' is available */
#define HAVE_PARAM_SET_UINT_MINMAX 1

/* 'PageError()()' is available */
/* #undef HAVE_PG_ERROR */

/* posix_acl_to_xattr() returns allocated buffer */
#define HAVE_POSIX_ACL_TO_XATTR_ALLOC_BUFFER 1

/* posix_acl_type() is available */
#define HAVE_POSIX_ACL_TYPE 1

/* prandom.h is present */
#define HAVE_PRANDOM_H 1

/* struct proc_ops exists */
#define HAVE_PROC_OPS 1

/* 'rb_find()' is available */
#define HAVE_RB_FIND 1

/* read_cache_folio() filler_t needs struct file */
#define HAVE_READ_CACHE_FOLIO_WANTS_FILE 1

/* register_shrinker() returns status */
/* #undef HAVE_REGISTER_SHRINKER_FORMAT_NAMED */

/* security_dentry_init_security needs lsm_context */
#define HAVE_SECURITY_DENTRY_INIT_SECURTY_WITH_CTX 1

/* security_dentry_init_security() returns xattr name */
/* #undef HAVE_SECURITY_DENTRY_INIT_WITH_XATTR_NAME_ARG */

/* security_inode_listsecurity() updates buffer and remaining size */
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 2, 0)
#define HAVE_SECURITY_INODE_LISTSECURITY_PTR_ARGS 1
#endif

/* security_sb_eat_lsm_opts is exported by the kernel */
#define HAVE_SECURITY_SB_EAT_LSM_OPTS 1

/* security_release_secctx has 1 arg. */
#define HAVE_SEC_RELEASE_SECCTX_1ARG 1

/* support for selinux */
#define HAVE_SELINUX 1

/* Define to 1 if you have the <selinux/selinux.h> header file. */
#define HAVE_SELINUX_SELINUX_H 1

/* sendpage_ok() is available */
#define HAVE_SENDPAGE_OK 1

/* support server */
#define HAVE_SERVER_SUPPORT 1

/* Define this if the Kerberos GSS library supports
   gss_krb5_set_allowable_enctypes */
/* #undef HAVE_SET_ALLOWABLE_ENCTYPES */

/* set_default_d_op exists */
#define HAVE_SET_DEFAULT_D_OP 1

/* set_posix_acl() has user namespace argument */
/* #undef HAVE_SET_POSIX_ACL_USER_NS */

/* 'sg_set_folio()' is available */
#define HAVE_SG_SET_FOLIO 1

/* 'shrinker_alloc()' exists */
#define HAVE_SHRINKER_ALLOC 1

/* simple_nosetlease() is available */
/* #undef HAVE_SIMPLE_NOSETLEASE */

/* sock_inuse_add() is available */
#define HAVE_SOCK_INUSE_ADD 1

/* sock_not_owned_by_me is defined in sock.h */
#define HAVE_SOCK_NOT_OWNED_BY_ME 1

/* Have spa_get_min_alloc_range in ZFS */
#define HAVE_SPA_GET_MIN_ALLOC_RANGE 1

/* Have spa_maxblocksize in ZFS */
#define HAVE_SPA_MAXBLOCKSIZE 1

/* Define to 1 if you have the 'statx' function. */
#define HAVE_STATX 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the 'strnlen' function. */
#define HAVE_STRNLEN 1

/* struct file has f_version */
/* #undef HAVE_STRUCT_FILE_F_VERSION */

/* struct lsm_context is available */
#define HAVE_STRUCT_LSM_CONTEXT 1

/* struct sockaddr_unsized exists */
#define HAVE_STRUCT_SOCKADDR_UNSIZED 1

/* Define to 1 if you have <sys/quota.h>. */
#define HAVE_SYS_QUOTA_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* task_is_running() is defined */
#define HAVE_TASK_IS_RUNNING 1

/* 'tcp_sock_set_keepcnt()' exists */
#define HAVE_TCP_SOCK_SET_KEEPCNT 1

/* 'tcp_sock_set_keepintvl()' exists */
#define HAVE_TCP_SOCK_SET_KEEPINTVL 1

/* 'tcp_sock_set_quickack()' exists */
#define HAVE_TCP_SOCK_SET_QUICKACK 1

/* timer_container_of() is available */
#define HAVE_TIMER_CONTAINER_OF 1

/* timer_delete() is available */
#define HAVE_TIMER_DELETE 1

/* timer_delete_sync() is available */
#define HAVE_TIMER_DELETE_SYNC 1

/* try_lookup_noperm() is available */
#define HAVE_TRY_LOOKUP_NOPERM 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* user_backed_iter() is available */
#define HAVE_USER_BACKED_ITER 1

/* use mnt_idmap in place of user_namespace argument */
#define HAVE_USER_NAMESPACE_ARG 1

/* uid_keyring exists */
/* #undef HAVE_USER_UID_KEYRING */

/* Have vdev_op_min_alloc in ZFS */
#define HAVE_VDEV_OP_MIN_ALLOC 1

/* 'vfsuid_t' and the i_uid_into_vfsuid() helpers exist */
#define HAVE_VFSUID_T 1

/* vfs_create() takes delegate */
#define HAVE_VFS_CREATE_DELEGATE 1

/* vfs_mkdir() takes delegate */
#define HAVE_VFS_MKDIR_DELEGATE 1

/* vfs_mmap_prepare() exists */
#define HAVE_VFS_MMAP_PREPARE 1

/* __vmalloc only takes 2 args. */
#define HAVE_VMALLOC_2ARGS 1

/* wait_on_page_locked() is available */
/* #undef HAVE_WAIT_ON_PAGE_LOCKED */

/* write_begin() takes folio */
#define HAVE_WRITE_BEGIN_FOLIO 1

/* write_begin() takes struct kiocb */
#define HAVE_WRITE_BEGIN_KIOCB 1

/* ZFS arc_prune_func_t uses uint64_t */
#define HAVE_ZFS_ARC_PRUNE_FUNC_UINT64 1

/* ZFS nvlist interfaces require const */
#define HAVE_ZFS_NVLIST_CONST_INTERFACES 1

/* Enable zfs osd */
#define HAVE_ZFS_OSD 1

/* Have zio_buf_alloc/free in ZFS */
#define HAVE_ZIO_BUF_ALLOC 1

/* __filemap_get_folio() exists */
#define HAVE___FILEMAP_GET_FOLIO 1

/* 'struct iov_iter' has '__iov' member */
#define HAVE___IOV_MEMBER __iov

/* if __ldiskfs_find_entry is available */
/* #undef HAVE___LDISKFS_FIND_ENTRY */

/* function pde_data() available */
#define HAVE_pde_data 1

/* (in kernel) 'IBK_SG_GAPS_REG' exists */
/* #undef IN_KERNEL_HAVE_IBK_SG_GAPS_REG */

/* (in kernel) FMR pools API available */
/* #undef IN_KERNEL_HAVE_OFED_FMR_POOL_API */

/* (in kernel) struct ib_device_ops is defined */
/* #undef IN_KERNEL_HAVE_OFED_IB_DEVICE_OPS */

/* (in kernel) if ib_dma_map_sg() is sane */
/* #undef IN_KERNEL_HAVE_OFED_IB_DMA_MAP_SG_SANE */

/* (in kernel) ib_dma_pci_p2p_dma_supported exists */
/* #undef IN_KERNEL_HAVE_OFED_IB_DMA_PCI_P2P_DMA_SUPPORTED */

/* (in kernel) ib_sg_dma_address wrapper exists */
/* #undef IN_KERNEL_HAVE_OFED_IB_SG_DMA_ADDRESS */

/* (in kernel) 'rdma_connect_locked' exists */
/* #undef IN_KERNEL_HAVE_OFED_RDMA_CONNECT_LOCKED */

/* (in kernel) 4arg 'rdma_reject' exists */
/* #undef IN_KERNEL_HAVE_OFED_RDMA_REJECT_4ARGS */

/* Define this as the Kerberos version number */
/* #undef KRB5_VERSION */

/* ext4_dir_rec_len takes a dir argument */
/* #undef LDISKFS_DIR_REC_LEN_WITH_DIR */

/* enable libcfs LASSERT, LASSERTF */
#define LIBCFS_DEBUG 1

/* buf bool arg */
#define LL_BFILL , B_FALSE

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Fourth number in the Lustre version */
#define LUSTRE_FIX 0

/* First number in the Lustre version */
#define LUSTRE_MAJOR 2

/* Second number in the Lustre version */
#define LUSTRE_MINOR 17

/* Third number in the Lustre version */
#define LUSTRE_PATCH 59

/* A copy of PACKAGE_VERSION */
#define LUSTRE_VERSION_STRING "in-kernel"

/* maximum number of MDS threads */
/* #undef MDS_MAX_THREADS */

/* Report minimum OST free space */
/* #undef MIN_DF */

/* name of ldiskfs mkfs program */
#define MKE2FS "mke2fs"

/* Name of package */
#define PACKAGE "lustre"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://jira.whamcloud.com/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "Lustre"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "Lustre 2.17.59"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "lustre"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.17.59"

/* struct page.flags as unsigned long */
#define PAGE_FLAGS(page) ((page)->flags.f)

/* name of parallel fsck program */
#define PFSCK "fsck"

/* 'PageError()' replacement */
#define PageError(pg) (0)

/* enable randomly alloc failure */
#define RANDOM_FAIL_ALLOC 1

/* no request_mask argument needed */
#define RQMASK_ARG 0,

/* The size of 'unsigned long long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG_LONG 8

/* Define to 1 if all of the C89 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* 'SetPageError()' replacement */
#define SetPageError(pg) /**/

/* name of ldiskfs tune program */
#define TUNE2FS "tune2fs"

/* Define this if the private function, gss_krb5_cache_name, must be used to
   tell the Kerberos library which credentials cache to use. Otherwise, this
   is done by setting the KRB5CCNAME environment variable */
/* #undef USE_GSS_KRB5_CCACHE_NAME */

/* Version number of package */
#define VERSION "2.17.59"

/* vfs_setxattr() value argument is non-const */
#define VFS_SETXATTR_VALUE(value) ((void *)(value))

/* "GDS build enabled" */
/* #undef WITH_EXTERNAL_GDS_HEADER */

/* zfs fix version */
#define ZFS_FIX 0

/* zfs major version */
#define ZFS_MAJOR 2

/* zfs minor version */
#define ZFS_MINOR 4

/* zfs patch version */
#define ZFS_PATCH 4

/* Tell ZFS we are kernel space code */
#define _KERNEL 1

/* dentry->__d_name is not available use d_name */
/* #undef __d_name */

/* file->__f_path is not available use f_path */
/* #undef __f_path */

/* 'struct iov_iter' has 'iov' member */
/* #undef __iov */

/* compat_capability_u32() is using u32 array */
#define compat_capability_u32(kcap) (kcap).val & 0xffffffff

/* compat_set_capability_u32() is using u32 array */
#define compat_set_capability_u32(kcap, val32) (kcap)->val = ((kcap)->val & 0xffffffff00000000ull) | (val32)

/* struct dentry d_children scans using list */
#define d_for_each_child(child, dentry) hlist_for_each_entry((child), &(dentry)->d_children, d_sib)

/* struct dentry d_children uses list */
#define d_no_children(dentry) hlist_empty(&(dentry)->d_children)

/* iov_iter_fault_in_readable()->fault_in_iov_iter_readable() */
/* #undef fault_in_iov_iter_readable */

/* Use fileattr for struct file_kattr */
/* #undef file_kattr */

/* fs_struct does not have seqlock: write_seqlock */
#define fs_write_seqlock(fs) write_seqlock(&(fs)->seq)

/* fs_struct does not have seqlock: write_sequnlock */
#define fs_write_sequnlock(fs) write_sequnlock(&(fs)->seq)

/* Use tuple_size for metadata_size */
#define get_metadata_size(bi) ((bi)->metadata_size)

/* get_random_u32() is not available, use prandom_u32 */
/* #undef get_random_u32 */

/* get_random_u32_below() is not available */
/* #undef get_random_u32_below */

/* grab_cache_page_write_begin() is unavailable */
#define grab_cache_page_write_begin(m, i) pagecache_get_page((m), (i), FGP_WRITEBEGIN, mapping_gfp_mask((m)))

/* hrtimer_setup() is unavailable */
/* #undef hrtimer_setup */

/* inode_state_read() does not exist, provide one */
/* #undef inode_state_read */

/* inode_state_read_once() does not exist, provide one */
/* #undef inode_state_read_once */

/* 'iov_iter()' provides iov */
/* #undef iter_iov */

/* need kmap_local_page map to atomic */
/* #undef kmap_local_page */

/* unuse_mm() -> kthread_unuse_mm() */
/* #undef kthread_unuse_mm */

/* use_mm() -> kthread_use_mm() */
/* #undef kthread_use_mm */

/* need kunmap_local map to atomic */
/* #undef kunmap_local */

/* dmu_assign_arcbuf_by_dbuf does not have flags arg */
#define ll_dmu_assign_arcbuf_by_dbuf(h, off, buf, tx, f) dmu_assign_arcbuf_by_dbuf((h), (off), (buf), (tx), (f))

/* dmu_buf_hold_array_by_bonus has 7 args */
#define ll_dmu_buf_hold_array_by_bonus(db, offset, len, read, tag, numbufsp, dbpp, flags) dmu_buf_hold_array_by_bonus((db), (offset), (len), (read), (tag), (numbufsp), (dbpp), (flags))

/* dmu_write_by_dnode does not have flags arg */
#define ll_dmu_write_by_dnode(dn, off, sz, buf, tx, f) dmu_write_by_dnode((dn), (off), (sz), (buf), (tx), (f))

/* lookup_noperm() was lookup_one_len() */
/* #undef lookup_noperm */

/* struct lsm_context also known as struct lsmcontext in ubuntu kernels */
/* #undef lsm_context */

/* netif_get_flags does not exist, use dev_get_flags */
/* #undef netif_get_flags */

/* real->posix_acl_to_xattr() */
/* #undef old_posix_acl_to_xattr */

/* function pde_data() unavailable */
/* #undef pde_data */

/* Use simple_dentry_operations to not cache dentries */
#define sb_dentry_not_cache(sb) ((sb)->s_d_flags |= DCACHE_DONTCACHE)

/* set_default_d_op not available */
/* #undef set_default_d_op */

/* struct sockaddr_unsized does not exist */
/* #undef sockaddr_unsized */

/* create compat task_is_running() */
/* #undef task_is_running */

/* timer_container_of() is not available */
/* #undef timer_container_of */

/* timer_delete() not is available */
/* #undef timer_delete */

/* timer_delete_sync() not is available */
/* #undef timer_delete_sync */

/* try_lookup_noperm() was d_hash_and_lookup() */
/* #undef try_lookup_noperm */

/* wait_on_page_locked() is unavailable */
#define wait_on_page_locked(page) folio_wait_locked(page_folio((page)))
