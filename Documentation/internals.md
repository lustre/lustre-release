# Lustre internals: a map of the code

A condensed guide to how Lustre is put together and where each part
lives in the tree, for developers and coding agents.  It points to files
and functions rather than line numbers; use `git grep` to find them.
Paths are relative to the top of the tree.

It was distilled from "Understanding Lustre Internals" (ORNL, 2021,
written against Lustre 2.15, linked from
https://wiki.lustre.org/Development) and checked against the 2.17/2.18
development tree.  Much of that document's detail on device setup,
libcfs and mounting no longer matches the code; where they disagree,
trust this file and the tree.  Other design notes in `Documentation/`:
`clio.txt` (client I/O), `osd-api.txt` (OSD API), `lfsck.txt`,
`dlc.txt` (LNet configuration), `ec.txt` (erasure coding),
`ladvise_lockahead.txt`, `lock-ordering`, `client_side_encryption/`
and `versioning.txt`.

## 1. The system

- Roles: the **MGS** holds configuration logs on its MGT and hands them
  out; **MDS** nodes serve the namespace from one or more **MDTs**; **OSS**
  nodes serve file data from **OSTs**; **clients** mount the filesystem.
  All traffic goes over **LNet**.  The MGS often shares a node or device
  with MDT0.
- Every object is named by a 128-bit FID (`struct lu_fid`: `f_seq`,
  `f_oid`, `f_ver`).  A file's MDT inode stores its layout in the
  `trusted.lov` xattr; a striped directory's layout is in `trusted.lmv`
  and a default directory layout in `trusted.dmv`.  OST objects carry a
  back-pointer to their file in `trusted.fid`, and every object stores
  its own FID in `trusted.lma`.
- A client opens a file through the MDT, receives the layout in the
  reply, and then does I/O directly to the OSTs.  Locks from the
  distributed lock manager (LDLM) keep client caches coherent.
- Servers store data through an OSD (object storage device) layer on
  ldiskfs (patched ext4), ZFS, or wbcfs (an experimental in-memory
  backend).

## 2. Modules

| Directory | Module | Notes |
|-----------|--------|-------|
| `lnet/libcfs/` | libcfs.ko | debug log, fail_loc, tunables; also links `lustre_compat/` |
| `lnet/lnet/`, `lnet/klnds/*`, `lnet/selftest/` | lnet.ko, k*lnd.ko, lnet_selftest.ko | networking |
| `lustre/obdclass/` | obdclass.ko | device model, lu_object, CLIO, llog, config, lprocfs |
| `lustre/ptlrpc/` (+ `ldlm/`, `target/`) | ptlrpc.ko | ldlm always linked in; target, nodemap and server NRS policies in server builds; `ptlrpc/gss/` is ptlrpc_gss.ko |
| `lustre/fid/`, `mgc/`, `ec/`, `obdecho/` | one each | always built |
| `lustre/llite/`, `lmv/`, `lov/`, `mdc/`, `osc/`, `fld/` | lustre.ko, ... | client (`CONFIG_LUSTRE_FS`); servers load fld too |
| `lustre/mgs/`, `mdt/`, `mdd/`, `lod/`, `osp/`, `ofd/`, `quota/`, `lfsck/` | one each | server (`CONFIG_LUSTRE_FS_SERVER`); quota is lquota.ko |
| `lustre/osd-ldiskfs/`, `osd-zfs/`, `osd-wbcfs/` | osd_*.ko | ldiskfs and zfs when configured; wbcfs in every server build |
| `lustre/kunit/` | test modules | `CONFIG_LUSTRE_FS_TESTS`; plain modules loaded by tests, not the kernel KUnit API |

Kernel code tests `CONFIG_LUSTRE_FS_SERVER` for server-only parts;
`SERVER_ONLY_EXPORT_SYMBOL` marks server-only exports.

## 3. Device model (`lustre/obdclass/`, `lustre/include/obd*.h`)

- `struct obd_type` describes a device type: `typ_dt_ops` (`struct
  obd_ops`), `typ_md_ops` (`struct md_ops`) and `typ_lu` (a
  `lu_device_type`).  Types register with `class_register_type()`.
- `struct obd_device` is one configured device (an OSC, an MDT, ...):
  name, UUID, `obd_flags` bitmap (`OBDF_ATTACHED`, `OBDF_SET_UP`,
  `OBDF_STOPPING`, ...), `obd_lu_dev`, its exports, and per-type unions
  such as `u.cli` for client devices.  All devices are in the `obd_devs`
  xarray; walk them with `obd_device_for_each*()` and look them up with
  `class_name2obd()`, `class_uuid2obd()` or `class_str2obd()`.
- `struct obd_ops` holds connection and data methods (`o_connect`,
  `o_disconnect`, `o_get_info`, `o_set_info_async`, `o_statfs`,
  `o_create`, `o_preprw`/`o_commitrw`, `o_iocontrol`, `o_import_event`,
  ...).  Callers use the `obd_xxx()` wrappers in `obd_class.h`, which
  check the method exists.  `struct md_ops` is the client metadata API,
  implemented by LMV and MDC and called through `md_xxx()` wrappers.
- Lifecycle, driven by configuration commands (`LCFG_*` in
  `include/uapi/linux/lustre/lustre_cfg.h`) through
  `class_process_config()`:
  - attach: `class_attach_name()` allocates the device, gives it a self
    export and registers it;
  - setup: `class_setup()` creates its hashes and calls `obd_setup()`,
    which runs the type's `ldto_device_alloc` and `ldto_device_init`;
  - cleanup: `class_cleanup()` disconnects exports and calls
    `obd_precleanup()` (`ldto_device_fini`);
  - detach: `class_detach()`; the last reference frees it through
    `obd_cleanup()` (`ldto_device_free`).
  `class_manual_cleanup()` does cleanup and detach at unmount.  Every
  type, including MGC, is an lu_device type now; there are no `o_setup`
  or `o_cleanup` methods.
- `lu_object` (`lustre/include/lu_object.h`, `obdclass/lu_object.c`) is
  the layered object model used by the server stacks and by CLIO on the
  client: one compound object has a slice per layer, found by FID in a
  per-site hash.  `dt_object` (`dt_object.h`) is the storage-level API
  every OSD, LOD and OSP implements.

## 4. Connections, imports and exports

- A client device (MDC, OSC, MGC, OSP, LWP) holds an **import** (`struct
  obd_import`, `lustre_import.h`) per target: connection, request lists
  for sending, replay and commit, and `imp_state` (`NEW`, `CONNECTING`,
  `REPLAY`, `RECOVER`, `FULL`, `EVICTED`, `IDLE`, ...).
  `client_obd_setup()` (`ldlm/ldlm_lib.c`) creates it.  The state
  machine is in `ptlrpc/import.c` (`ptlrpc_connect_import()`,
  `ptlrpc_import_recovery_state_machine()`) and `ptlrpc/recover.c`, and
  it signals `IMP_EVENT_*` to the device through `obd_import_event()`.
- A server has an **export** (`struct obd_export`, `lustre_export.h`)
  per connected client, created in `target_handle_connect()`
  (`ldlm/ldlm_lib.c`) together with a reverse import for callbacks.
  The export's handle cookie identifies the connection.
- LWP (light-weight proxy, `osp/lwp_dev.c`) connections from OSTs and
  MDTs to MDTs carry quota and FLD traffic.

## 5. Client

**Mount.**  `lustre_fs_type` in `llite/super25.c` uses the kernel's
fs_context API: `lustre_get_tree()` calls `lustre_fill_super()`, which
starts the MGC with `lustre_start_mgc()` (`obdclass/obd_mount.c`) and then
calls `ll_fill_super()` (`llite/llite_lib.c`).  That processes the client
configuration log (`<fsname>-client`) through the MGC, which creates and
sets up the LMV, MDCs, LOV and OSCs, then `client_common_fill_super()`
connects them.  Servers mount with filesystem type `lustre_tgt`
(`target/tgt_mount.c`); mounting a target as `lustre` is deprecated.

**VFS entry points** (llite): the `ll_file_operations_*` variants
generated in `file.c` (chosen by `ll_select_file_operations()` from the
flock mount option), `ll_file_inode_operations` (`file.c`),
`ll_dir_inode_operations` (`namei.c`), `ll_dir_operations` (`dir.c`),
`ll_aops` (`rw26.c`), `ll_file_vm_ops` (`llite_mmap.c`),
`lustre_super_operations` (`super25.c`).  Other llite features:
statahead (`statahead.c`), PCC (`pcc.c`), client encryption
(`crypto.c`), xattr cache, NFS export.

**Metadata path.**  llite calls `md_*()` -> LMV (`lmv/`, picks the MDT
from the FID via FLD or from the directory's name hash) -> MDC
(`mdc_intent_lock()`, `mdc_enqueue()` in `mdc/mdc_locks.c`; reint
operations in `mdc_reint.c`) -> `ldlm_cli_enqueue()` -> ptlrpc.  Most
metadata operations are intent locks: the lock request carries the
operation and the reply carries the result.

**Data path: CLIO** (`lustre/include/cl_object.h`, generic code in
`obdclass/cl_*.c`, design in `Documentation/clio.txt`).
`ll_file_read_iter()`/`ll_file_write_iter()` -> `ll_file_io_generic()`
-> `cl_io_loop()`, through the layers vvp (`llite/vvp_*.c`) -> lov and
lovsub (`lov/lov_io.c`, `lov_object.c`) -> osc (`osc/osc_io.c`, page
cache and extents in `osc_cache.c`, RPCs built in `osc_build_rpc()` in
`osc_request.c`).  Data-on-MDT components go to an MDC device under LOV
(`lov_dev.c`, `mdc/mdc_dev.c`).

## 6. RPCs and locking

**ptlrpc** (`lustre/ptlrpc/`): `ptlrpc_request` construction and
packing (`client.c`, `pack_generic.c`, request formats in `layout.c`),
synchronous `ptlrpc_queue_wait()`, request sets and the `ptlrpcd`
threads (`ptlrpcd.c`), sending and bulk transfer (`niobuf.c`,
`events.c`), the server side of services and threads (`service.c`), the
pinger, recovery and replay, NRS request scheduling policies (`nrs*.c`:
fifo, crr, orr, tbf, delay), security flavours (`sec*.c`, Kerberos and
shared-key in `gss/`), and nodemap (`nodemap_*.c`).

**LDLM** (`lustre/ldlm/`): namespaces, resources (named by FID) and locks.
Lock types: plain (`ldlm_plain.c`, MGS configuration and quota), extent
(`ldlm_extent.c`, file data on OSTs), inode bits (`ldlm_inodebits.c`,
metadata, and Data-on-MDT data with the `MDS_INODELOCK_DOM` bit) and flock
(`ldlm_flock.c`).  `ldlm_request.c` is the client side, `ldlm_lockd.c` the
server and callback threads, `ldlm_lock.c` the common lock state,
`ldlm_cache_policy.c` the client lock LRU policies, `ldlm_pool.c` LRU
sizing, and `ldlm_reclaim.c` the server lock memory limits.  Lock value
blocks (LVB) return file size and other state with a lock.

## 7. Servers

**Common target layer** (`lustre/target/`, `struct lu_target`): every
MDT and OST service uses `tgt_request_handle()` (`tgt_handler.c`),
which dispatches on opcode through handler tables: `mdt_tgt_handlers`,
`ofd_tgt_handlers`, and common tables for OBD, DLM, llog, security and
LFSCK requests.  It also holds bulk I/O (`tgt_brw_read()`,
`tgt_brw_write()`), last_rcvd and reply reconstruction for recovery
(`tgt_lastrcvd.c`), grants (`tgt_grant.c`), the server mount
(`tgt_mount.c`), the write barrier, and the OUT update handler and
distributed-transaction update logs used by DNE (`out_handler.c`,
`update_trans.c`, `update_recovery.c`).

**Metadata stack**: each layer is a slice of one compound lu_object.
```
tgt -> MDT (mdt/)  --md_object API (md_object.h)-->
       MDD (mdd/)  --dt_object API (dt_object.h)-->
       LOD (lod/)  --dt_object API-->  local OSD,  or OSP -> remote OST/MDT
```
- MDT: request parsing, intents (`mdt_intent_policy()`), reint
  operations (`mdt_reint.c`), open (`mdt_open.c`), Data-on-MDT I/O
  (`mdt_io.c`), HSM coordinator (`mdt_coordinator.c`, `mdt_hsm*.c`),
  directory restriping (`mdt_restripe.c`), batched RPCs.
- MDD: POSIX semantics, permissions and ACLs, changelogs
  (`mdd_changelog.c`, `mdd_device.c`), orphan handling.
- LOD: layouts and striping; OST and MDT allocation (`lod_qos.c`,
  round-robin and weighted QOS); PFL instantiation, FLR mirror state and
  self-extending layouts (`lod_object.c`); pools.
- OSP: proxy for remote objects: OST object precreation
  (`osp_precreate.c`), asynchronous destroy and setattr through llogs
  (`osp_sync.c`), remote MDT objects for DNE (`osp_md_object.c`).

**Data stack**: tgt -> OFD (`ofd/`, "OBD Filter Device", obd type
`obdfilter`; `ofd_preprw()`/`ofd_commitrw()` in `ofd_io.c`) -> OSD.  The
OSS services (`ost`, `ost_io`, `ost_create`, ...) are registered in
`ofd/ofd_oss.c`.

**Other servers**: MGS (`mgs/`: configuration llogs in `mgs_llog.c`,
imperative recovery in `mgs_nids.c`); quota master on MDT0 (`qmt_*`)
and slaves on every target (`qsd_*`); LFSCK (`lfsck/`, see
`Documentation/lfsck.txt`).

## 8. OSD and on-disk format

- The OSD API (`dt_object.h`, `Documentation/osd-api.txt`) gives the
  layers above objects, indexes, xattrs and transactions independent
  of the backend.
- **osd-ldiskfs** calls ldiskfs internally (not through the VFS).  The
  object index (OI) maps FIDs to inodes: IAM index files `oi.16.N`, 64
  by default (`osd_oi.c`, `osd_iam*.c`), with a per-thread lookup cache.
  OST objects, llog objects and IDIF FIDs bypass the OI and live in the
  `O/<seq>/d<N>/<oid>` directory tree (`osd_compat.c`).  OI scrub
  (`osd_scrub.c`) rebuilds the OI from each inode's `trusted.lma`.
  ldiskfs itself is ext4 plus the patch series in
  `ldiskfs/kernel_patches/`.
- **osd-zfs** uses the DMU, ZAP and SA interfaces directly, with 128 ZAP
  OIs named `oi.N` and per-sequence ZAPs under `O` for OST objects.
- **osd-wbcfs** is an experimental in-memory backend without an OI.

## 9. FIDs, sequences and FLD

- `struct lu_fid` is in `include/uapi/linux/lustre/lustre_user.h`; the
  reserved sequences (`enum fid_seq`) are in `lustre_idl.h`: IGIF
  (old ext3-style inode/generation FIDs), IDIF (OST objects from before
  FIDs on OSTs: bit 32 set, OST index in bits 16-31), local-file and
  special sequences, and `FID_SEQ_NORMAL` (0x200000400) onwards for
  ordinary objects.  Fixed local object IDs are `enum local_oid` in
  `lustre/include/lustre_fid.h`.  On OST objects, `f_ver` in the parent
  FID holds the stripe index.
- Sequence allocation (`lustre/fid/`): MDT0 runs the sequence controller
  that hands out super-sequences; each MDT serves metadata sequences to
  clients, and each OST serves data sequences to the OSPs on the MDTs.
  Clients get sequences only from MDTs (`client_fid_init()`,
  `seq_client_alloc_fid()`, called through LMV and MDC).
- FLD (`lustre/fld/`) maps a sequence range to the MDT or OST that owns
  it.  The full table is on MDT0; clients and servers cache lookups
  (`fld_client_lookup()`, `fld_server_lookup()`).

## 10. Layouts and DNE

- File layouts: `lov_mds_md_v1`/`v3` (plain RAID0, v3 adds a pool name)
  in `lustre_idl.h`; composite layouts are `lov_comp_md_v1` with
  `lov_comp_md_entry_v1` components (`lustre_user.h`).  Magics are
  `LOV_MAGIC_V1`, `_V3`, `_COMP_V1`, `_FOREIGN` and `_SEL`.
- Stripe patterns (`LOV_PATTERN_*`): RAID0, MDT (Data-on-MDT),
  OVERSTRIPING (several stripes per OST), FOREIGN, PARITY (erasure-coded
  parity), and F_RELEASED for HSM-released files.
- Component flags (`LCME_FL_*`): INIT (instantiated), STALE, PREF_RD/WR
  and NOSYNC for FLR mirrors, EXTENSION for self-extending layouts
  (SEL), and PARITY.
- PFL (progressive file layouts) instantiates components as the file
  grows.  FLR (file-level replication) keeps mirrors; the mirror ID is
  bits 16-30 of `lcme_id`, and the file state (`LCM_FL_RDONLY`,
  `WRITE_PENDING`, `SYNC_PENDING`) is in `lcm_flags`.  Erasure coding adds
  parity components linked to data mirrors in the layout
  (`LCME_FL_PARITY`, `Documentation/ec.txt`); `lustre/ec/` holds only the
  Reed-Solomon parity math.  The server side is in `lod/lod_object.c`; the
  client unpacks layouts in `lov/lov_ea.c`; userspace uses
  `llapi_layout_*`.
- Defaults: stripe count 1, stripe size 4 MiB; minimum stripe size
  64 KiB, maximum stripe count 2000.
- Directories (DNE): a remote directory lives on another MDT (`lfs mkdir
  -i N`); a striped directory spreads its entries over several MDTs by
  name hash (`lmv_mds_md_v1`, hash types `LMV_HASH_TYPE_*`, default
  FNV-1a 64).  The root directory has a default layout that spreads new
  top-level directories over MDTs.  Directories can be migrated (`lfs
  migrate -m`) and automatically split when they grow (`mdt_restripe.c`,
  off by default).

## 11. llog and configuration logs

- llog (`obdclass/llog*.c`, `ptlrpc/llog_*.c`) stores records in plain
  logs and catalogs of logs: configuration, changelogs, OSP sync logs,
  DNE update logs.  Record types (`enum llog_op_type`) are in
  `lustre_idl.h`.  API: `llog_open()`, `llog_init_handle()`,
  `llog_process()`, `llog_add()`; `llog_osd_ops` read local storage and
  `llog_client_ops` read remotely from the MGS.
- Configuration: the MGS writes `<fsname>-client`, `<fsname>-MDT0000`,
  `<fsname>-OST0000`, `params`, `<fsname>-sptlrpc` and other logs.
  `mgc_process_config()` registers a log and its dependent logs
  (`config_log_add()`), takes a plain DLM lock on each
  (`mgc_process_log()`), and replays the records through
  `class_config_llog_handler()` into `class_process_config()`.  When the
  configuration changes, the MGS revokes the lock and the MGC's requeue
  thread reads the new records.  Servers keep local copies in `CONFIGS/`
  so they can start without the MGS; clients don't.
- `lctl set_param -P` and `lctl conf_param` store parameters on the MGS;
  `lctl --device MGS llog_print <log>` shows a log.

## 12. LNet

- Core (`lnet/lnet/`): network interface setup (`api-ni.c`, also the
  generic-netlink configuration interface), `LNetPut()`/`LNetGet()` and
  message send and receive (`lib-move.c`), multi-rail peers (`peer.c`),
  routing (`router.c`), UDSP selection policies (`udsp.c`), and fault
  injection (`net_fault.c`).  CPU partition tables (`lib-cpt.c`) and the
  checksum wrappers (`lnet-crypto.c`) also live here.
- LNDs (`lnet/klnds/`): socklnd (TCP), o2iblnd (InfiniBand, RoCE,
  OmniPath; `in-kernel-o2iblnd/` builds it against the kernel's own
  RDMA stack), gnilnd (Cray Gemini/Aries), kfilnd (HPE kfabric) and
  efalnd (AWS EFA).
- Headers: `include/linux/lnet/` (kernel) and `include/uapi/linux/lnet/`
  (shared); `lnet/include/` has only `udsp.h`.  Userspace: `lnetctl`,
  `lst` and the `liblnetconfig` library in `lnet/utils/`; see
  `Documentation/dlc.txt`.  `lnet/selftest/` is the LNet self-test.

## 13. libcfs: debugging and fault injection

- libcfs.ko is `lnet/libcfs/` plus `lustre_compat/`.  Its headers are
  `include/linux/libcfs/`.  Former libcfs pieces moved: CPU partitions
  and checksums to LNet, `cfs_hash` to `obdclass/hash.c`, client
  encryption (llcrypt, an fscrypt fork; `--enable-crypto=in-kernel`
  uses the kernel's fscrypt instead) to `lustre_compat/fs/crypto/`,
  and the userspace parser and NID helpers to `lib/libcfs/`.
- Debug log: each kernel file sets `DEBUG_SUBSYSTEM`; `CDEBUG(mask, ...)`
  writes to a per-CPU trace buffer when the mask and subsystem are enabled
  (`lctl set_param debug=...`), and `lctl dk` dumps it.  Masks and
  subsystems are in `include/uapi/linux/lnet/libcfs_debug.h`.  `CERROR`,
  `CWARN` and `CEMERG` are always logged and rate limited; `CNETERR` is
  rate limited and on by default, but can be masked off.
  `ENTRY`/`EXIT`/`RETURN`/`GOTO` log at `D_TRACE`.  `LASSERT`/`LBUG` are
  in `libcfs_private.h`.
- Fault injection: `CFS_FAIL_CHECK(id)`, `CFS_FAIL_TIMEOUT()`,
  `CFS_RACE()` and related macros in `include/linux/libcfs/libcfs_fail.h`
  fire when `fail_loc` matches.  Lustre IDs are `OBD_FAIL_*` in
  `lustre/include/obd_support.h`, grouped by subsystem (MDS 0x100, OST
  0x200, LDLM 0x300, OSC 0x400, PTLRPC 0x500, ...); LNet uses
  0xe000-0xefff and LNDs 0xf000-0xffff.  Flag bits such as
  `CFS_FAIL_ONCE` (0x80000000) control how often a point fires.  Tests
  set `fail_loc` and `fail_val` with `lctl set_param` on the node
  concerned.

## 14. Userspace

- `lustre/utils/`: `lfs` (`lfs.c`: setstripe, getstripe, mirror,
  migrate, mkdir, find, quota, hsm, pcc, ...), `lctl` (command table in
  `lctl.c`; handlers in `obd.c`, `lustre_cfg.c`, `lustre_param.c`,
  `debug.c`, `portals.c`), `mkfs.lustre` and `tunefs.lustre` (both from
  `mkfs_lustre.c`, with backend code in `libmount_utils_*.c`),
  `mount.lustre` (`mount_lustre.c`; `mount.lustre_tgt` is a link to it),
  and server tools such as `llog_reader` and `lr_reader`.
- liblustreapi (`lustre/utils/liblustreapi*.c`, public header
  `include/lustre/lustreapi.h`) is the userspace library for layouts,
  FIDs, changelogs, HSM and quotas.  `rustreapi/` wraps it for Rust.
- `lustre/scripts/` and `lustre-iokit/` hold administrative scripts and
  benchmarks (obdfilter-survey, ost-survey, mds-survey, ...).  Man pages
  are in `Documentation/man*/`.

## 15. Build and kernel compatibility

- `sh autogen.sh && ./configure && make`.  Configure checks each kernel
  API difference with a pair of macros (e.g. `LC_SRC_*` building a test
  with `LB2_LINUX_TEST_SRC`, `LC_*` defining `HAVE_*` from the result),
  mostly in `config/lustre-core.m4`, plus `lustre-libcfs.m4`,
  `lustre-lnet.m4` and the ldiskfs and ZFS files.
- Compatibility wrappers are in `include/lustre_compat/`, named after
  the kernel header they extend, with code in `lustre_compat/`.
  `lustre/include/lustre_compat.h` is the older catch-all.
- Code meant to be removed in a later release is wrapped in `#if
  LUSTRE_VERSION_CODE < OBD_OCD_VERSION(...)`.

## 16. Tests

`lustre/tests/` holds the test suites, run by `auster` on top of
`test-framework.sh`; `test-groups/regression` lists the regression set.
`cfg/local.sh` describes the default single-node setup (loop devices,
one MDT, two OSTs).  The lustre-test-scripts skill in `.agents/skills/`
covers running and writing tests.
