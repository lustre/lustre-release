// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::{
    Fid, LustrePath,
    error::{Result, cvt_lz_m, cvt_nz_m, cvt_rc_m},
    hsm::user::HsmRequestFlags,
};
use lustreapi_sys::*;
use serde::{Deserialize, Serialize};
use std::{
    alloc,
    alloc::{Layout, alloc},
    ffi::CString,
    fmt,
    fmt::Display,
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
    ptr::NonNull,
};

/// A safe wrapper around a raw file descriptor with automatic cleanup.
///
/// `RawDescriptor` encapsulates a file descriptor obtained from Lustre HSM operations
/// and is specifically designed for use with `tokio::AsyncFd` for asynchronous event polling.
/// It implements `AsRawFd` for API compatibility and automatically closes the descriptor
/// when dropped, preventing resource leaks.
///
/// # Safety
///
/// This struct takes ownership of the provided file descriptor. The descriptor should not
/// be used directly after being wrapped or after the `RawDescriptor` is dropped.
pub struct RawDescriptor(i32);

impl RawDescriptor {
    /// Creates a new `RawDescriptor` by taking ownership of the provided file descriptor.
    pub fn new(fd: i32) -> Self {
        Self(fd)
    }
}
impl AsRawFd for RawDescriptor {
    /// Returns the underlying raw file descriptor.
    ///
    /// Note that the returned descriptor is still owned by this `RawDescriptor`
    /// and will be closed when dropped.
    fn as_raw_fd(&self) -> i32 {
        self.0
    }
}
impl Drop for RawDescriptor {
    /// Closes the file descriptor automatically when the `RawDescriptor` is dropped.
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

pub trait MoverRef {
    fn mover_ref(&self) -> *const hsm_copytool_private;
}

#[derive(Default)]
pub struct CopytoolBuilder {
    archives: Vec<i32>,
    non_blocking: bool,
}

/// Builder for configuring and registering a Lustre HSM Copytool connection.
///
/// `CopytoolBuilder` allows you to customize how the `Copytool` connects to
/// the HSM coordinator, including which archives it will service and whether
/// operations should be non-blocking.
///
/// # Usage
/// See the `Copytool` struct for more details.
///
/// # Methods
///
/// - `archives()`: Specify which archive IDs this copytool will service
/// - `non_blocking()`: Configure whether operations should be non-blocking
/// - `register()`: Connect to the HSM coordinator and create the `Copytool`
///
/// When no archives are specified, the copytool will service all archives.
impl CopytoolBuilder {
    /// Specifies which archive IDs this copytool will service.
    ///
    /// # Arguments
    ///
    /// * `archives` - Vector of archive IDs to service. Each ID typically corresponds to a
    ///   different storage tier in the HSM system.
    ///
    /// # Default
    ///
    /// If not called, the copytool will service all available archives.
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    pub fn archives(mut self, archives: Vec<i32>) -> Self {
        self.archives = archives;
        self
    }

    /// Controls whether the copytool should use non-blocking I/O.
    ///
    /// # Arguments
    ///
    /// * `non_blocking` - When `true`, attempts to read when no data is available
    ///   will return immediately with `EWOULDBLOCK` or `EAGAIN` errors, suitable for
    ///   event-driven applications. When `false` (default), read operations will
    ///   block until data is available.
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    pub fn non_blocking(mut self, non_blocking: bool) -> Self {
        self.non_blocking = non_blocking;
        self
    }

    /// Registers the copytool with the Lustre HSM coordinator.
    ///
    /// This finalizes the copytool configuration and establishes a connection
    /// with the HSM coordinator on the specified Lustre filesystem.
    ///
    /// # Arguments
    ///
    /// * `mount_dir` - Path to a Lustre filesystem mount point
    ///
    /// # Returns
    ///
    /// * `Result<Copytool>` - A registered copytool instance on success, or an error
    ///   if registration fails (e.g., if the coordinator is unavailable or the path
    ///   is not a valid Lustre mount point)
    pub fn register(self, mount_dir: &LustrePath) -> Result<Copytool> {
        let flags = if self.non_blocking {
            libc::O_NONBLOCK
        } else {
            0
        };
        let cstr = CString::new(mount_dir.as_ref().as_os_str().as_encoded_bytes())?;
        let mut inner: *mut hsm_copytool_private = std::ptr::null_mut();

        unsafe {
            cvt_rc_m(
                llapi_hsm_copytool_register(
                    &mut inner as *mut *mut hsm_copytool_private,
                    cstr.as_ptr(),
                    self.archives.len() as i32,
                    self.archives.as_ptr() as *mut i32,
                    flags,
                ),
                "Failed to register copytool".to_string(),
            )
            .map(|_| Copytool { inner })
        }
    }
}

/// Interface for receiving and processing Lustre HSM actions from the coordinator.
///
/// `Copytool` provides a connection to the Lustre HSM coordinator, allowing applications
/// to receive action requests (archive, restore, remove, etc.) from the filesystem. It acts
/// as the communication channel between the HSM system and actual data movement operations.
///
/// # Usage
///
/// Create a `Copytool` using the builder pattern:
/// ```no_run
/// # use std::error::Error;
/// # fn example() -> Result<(), Box<dyn Error>> {
/// use rustreapi::hsm::Copytool;
/// use rustreapi::LustrePath;
///
/// let mount_path = LustrePath::parse("/mnt/lustre")?;
///
/// // Create a copytool watching archive IDs 1 and 2
/// let copytool = Copytool::builder()
///     .archives(vec![1, 2])
///     .register(&mount_path)
///     .expect("Copytool registration");
///
/// // Receive action requests
/// let action_list = copytool.receive()?;
/// # Ok(())
/// # }
/// ```
///
/// # Event-driven Processing
///
/// For event-driven applications, use `raw_fd()` to get a file descriptor
/// that can be monitored with `poll()`, `select()`, or integration with event
/// loops like Tokio:
///
/// ```no_run
/// # use std::error::Error;
/// # fn example() -> Result<(), Box<dyn Error>> {
/// # use rustreapi::hsm::Copytool;
/// # use rustreapi::LustrePath;
/// # let mount_path = LustrePath::parse("/mnt/lustre")?;
/// // Create a copytool watching all archives
/// let copytool = Copytool::builder()
///     .non_blocking(true)
///     .register(&mount_path)
///     .expect("Copytool registration");
///
/// let fd = copytool.raw_fd()?;
/// // Use fd with event notification systems
/// # Ok(())
/// # }
/// ```
///
/// # Cleanup
///
/// The `Copytool` automatically unregisters from the HSM coordinator when dropped.
///
/// # Related Types
///
/// - `CopytoolBuilder`: Configures and creates `Copytool` instances
/// - `ActionList`: Collection of HSM action items received from coordinator
/// - `ActionItem`: Individual HSM operation to be performed
/// - `Mover`: Interface for data movement operations
#[derive(Debug)]
pub struct Copytool {
    inner: *mut hsm_copytool_private,
}

/// Constructor
impl Copytool {
    pub fn builder() -> CopytoolBuilder {
        CopytoolBuilder::default()
    }
}

impl Drop for Copytool {
    /// Clean up the `Copytool` instance by
    /// calling `unregister()` if pointer is
    /// still valid.
    fn drop(&mut self) {
        if !self.inner.is_null() {
            self.unregister()
                .expect("Copytool should be valid before calling unregister.");
        }
    }
}

/// `Copytool` provides a connection to the `coordinator` and
/// returns lists of `ActionItems`. It can also be used to create a
/// `Mover` to process actions.
impl Copytool {
    /// Unregister the `Copytool` instance from the HSM coordinator.
    ///
    /// This method is called automatically when the `Copytool` is dropped,
    /// so manual calls are typically unnecessary. It releases resources
    /// held by the HSM coordinator for this copytool.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the unregistration.
    fn unregister(&mut self) -> Result<()> {
        unsafe {
            let result = cvt_rc_m(
                llapi_hsm_copytool_unregister(&mut self.inner as *mut *mut hsm_copytool_private),
                "Failed to unregister copytool".to_string(),
            );
            assert!(self.inner.is_null());
            result
        }
    }

    /// Receive HSM action requests from the coordinator.
    ///
    /// This method blocks until action items are available, unless the
    /// copytool was configured as non-blocking. In non-blocking mode,
    /// it will return immediately with an `EWOULDBLOCK` error if no
    /// actions are available.
    ///
    /// # Returns
    ///
    /// * `Ok(ActionList)` - A list of HSM actions to be processed
    /// * `Err` - If there was an error receiving actions from the coordinator
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::error::Error;
    /// # fn example() -> Result<(), Box<dyn Error>> {
    /// # use rustreapi::hsm::Copytool;
    /// # use rustreapi::LustrePath;
    /// # let mount_path = LustrePath::parse("/mnt/lustre")?;
    /// # let copytool = Copytool::builder().register(&mount_path)?;
    /// // Process actions in a loop
    /// loop {
    ///     match copytool.receive() {
    ///         Ok(action_list) => {
    ///             // Process the action list
    ///             for action in action_list.iter() {
    ///                 // Handle each action...
    ///             }
    ///         },
    ///         Err(e) => {
    ///             // Handle errors (like EWOULDBLOCK in non-blocking mode)
    ///             break;
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn receive(&self) -> Result<ActionList> {
        let mut hal: *mut hsm_action_list = std::ptr::null_mut();
        let mut msg_len = 0;
        unsafe {
            cvt_rc_m(
                llapi_hsm_copytool_recv(self.inner, &mut hal, &mut msg_len),
                "Failed to receive copytool message".to_string(),
            )?;

            Ok(ActionList::new(hal, msg_len as usize))
        }
    }

    /// Returns a file descriptor that can be used with event notification systems.
    ///
    /// This method is particularly useful for integrating the copytool with
    /// event-driven frameworks like `epoll`, `poll`, `select`, or async runtimes
    /// like Tokio. When events are available on this file descriptor,
    /// `receive()` can be called to retrieve the available action items.
    ///
    /// # Returns
    ///
    /// * `Ok(RawDescriptor)` - A wrapper around the file descriptor that will
    ///   automatically close it when dropped
    /// * `Err` - If there was an error obtaining the file descriptor
    ///
    /// # Example with Tokio
    ///
    /// ```no_run
    /// # use std::error::Error;
    /// # fn example() -> Result<(), Box<dyn Error>> {
    /// # use rustreapi::hsm::Copytool;
    /// # use rustreapi::LustrePath;
    /// # let mount_path = LustrePath::parse("/mnt/lustre")?;
    /// let copytool = Copytool::builder()
    ///     .non_blocking(true)
    ///     .register(&mount_path)?;
    ///
    /// let fd = copytool.raw_fd()?;
    ///
    /// // The file descriptor can now be used with tokio::io::unix::AsyncFd
    /// // or similar event notification mechanisms
    /// # Ok(())
    /// # }
    /// ```
    pub fn raw_fd(&self) -> Result<RawDescriptor> {
        unsafe {
            cvt_lz_m(
                llapi_hsm_copytool_get_fd(self.inner),
                "Failed to get copytool fd".to_string(),
            )
            .map(RawDescriptor::new)
        }
    }
}

impl MoverRef for &Copytool {
    fn mover_ref(&self) -> *const hsm_copytool_private {
        self.inner
    }
}

/// Builder for creating a connection to the Lustre HSM mover interface.
///
/// `MoverBuilder` creates a `Mover` instance which provides the capability
/// to interact with the Lustre HSM data movement interface.
///
/// # Usage
///
/// Se
///
/// Unlike `CopytoolBuilder`, `MoverBuilder` doesn't have configuration options
/// since the mover interface is simpler.
pub struct MoverBuilder {}
impl MoverBuilder {
    /// Registers a new mover with the Lustre HSM coordinator.
    ///
    /// This method establishes a connection with the HSM system on the
    /// specified Lustre filesystem, allowing the application to perform
    /// data movement operations.
    ///
    /// # Arguments
    ///
    /// * `mount_dir` - Path to a Lustre filesystem mount point
    ///
    /// # Returns
    ///
    /// * `Result<Mover>` - A registered mover instance on success, or an error
    ///   if registration fails (e.g., if the coordinator is unavailable or the path
    ///   is not a valid Lustre mount point)
    ///
    pub fn register(self, mount_dir: &LustrePath) -> Result<Mover> {
        let cstr = CString::new(mount_dir.as_ref().as_os_str().as_encoded_bytes())?;
        let mut inner: *mut hsm_mover_private = std::ptr::null_mut();
        unsafe {
            cvt_rc_m(
                llapi_hsm_mover_register(&mut inner as *mut *mut hsm_mover_private, cstr.as_ptr()),
                "Failed to register copytool".to_string(),
            )?;
        }
        Ok(Mover { inner })
    }
}

/// Represents a connection to the Lustre HSM mover interface for processing data transfers.
///
/// A `Mover` provides the capability to move data between storage tiers in a Lustre
/// Hierarchical Storage Management (HSM) system. It allows processing action items through
/// the HSM data movement interface.
///
/// # Usage
///
/// Create a `Mover` using the builder pattern:
///
/// ```no_run
/// # use std::error::Error;
/// # fn example() -> Result<(), Box<dyn Error>> {
/// use rustreapi::hsm::Mover;
/// use rustreapi::LustrePath;
///
/// let mount_path = LustrePath::parse("/mnt/lustre")?;
/// let mover = Mover::builder().register(&mount_path)?;
/// # Ok(())
/// # }
/// ```
///
/// # Cleanup
///
/// The `Mover` will automatically unregister itself when dropped. If you need to
/// unregister earlier, you can call the `unregister()` method directly.
///
/// # Related Types
///
/// - `MoverBuilder`: Used to configure and create a `Mover` instance
/// - `ActionProgress`: Used with a `Mover` to track and update progress during operations
/// - `Copytool`: Interface for receiving HSM actions from the Lustre coordinator
#[derive(Debug)]
#[repr(transparent)]
pub struct Mover {
    inner: *mut hsm_mover_private,
}

unsafe impl Send for Mover {}
unsafe impl Sync for Mover {}

impl Drop for Mover {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            self.unregister()
                .expect("Copytool should be valid before calling unregister.");
        }
    }
}

impl Mover {
    pub fn builder() -> MoverBuilder {
        MoverBuilder {}
    }

    /// Unregister the `Mover` instance from the HSM coordinator.
    ///
    /// This method is called automatically when the `Mover` is dropped,
    /// so manual calls are typically unnecessary. It releases resources
    /// held by the HSM coordinator for this mover.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the unregistration.
    fn unregister(&mut self) -> Result<()> {
        unsafe {
            let result = cvt_rc_m(
                llapi_hsm_mover_unregister(&mut self.inner as *mut *mut hsm_mover_private),
                "Failed to unregister copytool".to_string(),
            );
            assert!(self.inner.is_null());
            result
        }
    }
}

impl MoverRef for &Mover {
    fn mover_ref(&self) -> *const hsm_copytool_private {
        unsafe {
            std::mem::transmute::<*const hsm_mover_private, *const hsm_copytool_private>(self.inner)
        }
    }
}

pub struct ProgressBuilder {}

impl ProgressBuilder {
    /// This is used to start processing an action.
    /// The returned `CopyAction` is used to update the progress
    /// and complete the action.
    pub fn action_begin(
        ct: impl MoverRef,
        action: &ActionItem,
        open_flags: i32,
    ) -> Result<ActionProgress> {
        Self::begin(ct, action, -1, open_flags, false)
    }

    /// If an action can't be processed or is cancelled, then use this
    /// instead of `action_begin()` and `action_end()`.
    pub fn action_error(
        ct: impl MoverRef,
        action: &ActionItem,
        retry: bool,
        err: i32,
    ) -> Result<()> {
        let mut ca = Self::begin(ct, action, -1, 0, true)?;

        let flag: i32 = if retry { HP_FLAG_RETRY as i32 } else { 0 };
        ca.end(action.extent.clone(), flag, err)?;
        Ok(())
    }
    fn begin(
        copytool: impl MoverRef,
        action: &ActionItem,
        mdt_idx: i32,
        open_flags: i32,
        is_error: bool,
    ) -> Result<ActionProgress> {
        let mut hcp: *mut hsm_copyaction_private = std::ptr::null_mut();
        let hai = action.to_native();

        unsafe {
            cvt_rc_m(
                llapi_hsm_action_begin(
                    &mut hcp as *mut *mut hsm_copyaction_private,
                    copytool.mover_ref(),
                    hai.as_ref(),
                    mdt_idx,
                    open_flags,
                    is_error,
                ),
                "Failed to begin copy action".to_string(),
            )?;

            Ok(ActionProgress { inner: hcp })
        }
    }
}

pub struct ActionProgress {
    inner: *mut hsm_copyaction_private,
}

unsafe impl Send for ActionProgress {}
unsafe impl Sync for ActionProgress {} // TODO: is this safe?

impl ActionProgress {
    pub fn dfid(&self) -> Result<Fid> {
        let mut dfid = lu_fid::default();
        unsafe {
            cvt_nz_m(
                llapi_hsm_action_get_dfid(self.inner, &mut dfid as *mut lu_fid),
                "Failed to get dfid".to_string(),
            )?;
        }
        Ok(Fid::from(dfid))
    }

    pub fn data_file(&self) -> Result<File> {
        unsafe {
            cvt_lz_m(
                llapi_hsm_action_get_fd(self.inner),
                "Failed to get fd".to_string(),
            )
            .map(|fd| File::from_raw_fd(fd))
        }
    }

    pub fn progress(&mut self, extent: Extent, total: u64, hp_flags: i32) -> Result<()> {
        let extent: hsm_extent = extent.into();

        unsafe {
            cvt_rc_m(
                llapi_hsm_action_progress(self.inner, &extent, total, hp_flags),
                "Failed to update copy action progress".to_string(),
            )
        }
    }

    ///
    /// Complete the copy action. This will free and null the inner pointer.
    /// This `CopyAction` must not be used after this.
    pub fn end(&mut self, extent: Extent, flag: i32, err: i32) -> Result<()> {
        let flag: i32 = if err == 0 && flag == 0 {
            HP_FLAG_COMPLETED as i32
        } else {
            0
        };
        let extent: hsm_extent = extent.into();
        unsafe {
            cvt_rc_m(
                llapi_hsm_action_end(&mut self.inner, &extent, flag, err),
                "Failed to end copy action".to_string(),
            )
        }
    }
}

/// Currently this wraps the native struct which contains
/// a list of variably sized action items.
#[derive(Debug)]
pub struct ActionList {
    // Pointer to memory allocated with libc and will
    // be freed when this struct is dropped.
    pub hal: NonNull<hsm_action_list>,
    alloc_size: usize,
}

impl ActionList {
    pub fn new(hal: *const hsm_action_list, size: usize) -> Self {
        // TODO: is this worth doing or should we just convert to directly to Vec<ActionItem>?
        let layout = Layout::from_size_align(size, align_of::<hsm_action_list>())
            .expect("Arguments should follow constraints of from_size_align.");
        let ptr = unsafe { alloc(layout) };

        let new_hal = match NonNull::new(ptr as *mut hsm_action_list) {
            Some(p) => p,
            None => alloc::handle_alloc_error(layout),
        };

        unsafe { std::ptr::copy(hal as *const u8, new_hal.as_ptr() as *mut u8, size) };

        Self {
            hal: new_hal,
            alloc_size: size,
        }
    }
}

impl Drop for ActionList {
    fn drop(&mut self) {
        unsafe {
            alloc::dealloc(
                self.hal.as_ptr() as *mut u8,
                Layout::from_size_align(self.alloc_size, align_of::<hsm_action_list>())
                    .expect("Arguments should follow constraints of from_size_align."),
            );
        }
    }
}

impl ActionList {
    pub fn len(&self) -> usize {
        unsafe { self.hal.as_ref().hal_count as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> ActionIterator<'_> {
        ActionIterator {
            list: self,
            next: 0,
            prev: None,
        }
    }
}

// Step through a list of hsm_action_items
// Because hsm_action_item is a variable length struct,
// we use the hai_first and hai_next to step through the
// list based on the previous item.

/// This iterator converts  the list of `hsm_action_items` in
///  into `Vec<ActionItem>` where `ActionItem`
/// is a native rust version of `hsm_action_item`.
///
pub struct ActionIterator<'a> {
    list: &'a ActionList,
    next: usize,
    prev: Option<&'a hsm_action_item>,
}

impl Iterator for ActionIterator<'_> {
    type Item = ActionItem;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.list.len() {
            return None;
        }

        let item = if let Some(prev) = self.prev {
            hai_next(prev)
        } else {
            hai_first(self.list.hal.as_ptr())
        };

        self.next += 1;
        self.prev = Some(item);
        Some(ActionItem::from(item))
    }
}

fn hai_first<'a>(hal: *const hsm_action_list) -> &'a hsm_action_item {
    unsafe { &(*hai_first__extern(hal)) }
}

fn hai_next<'a>(hai: &hsm_action_item) -> &'a hsm_action_item {
    unsafe { &(*hai_next__extern(hai)) }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionHeader {
    pub archive_id: u32,
    pub flags: HsmRequestFlags,
    pub actions: Vec<ActionItem>,
}

impl From<ActionList> for ActionHeader {
    fn from(al: ActionList) -> Self {
        let items: Vec<ActionItem> = al.iter().collect();
        let hal = unsafe { al.hal.as_ref() };
        Self {
            archive_id: hal.hal_archive_id,
            flags: HsmRequestFlags::from(hal.hal_flags),
            actions: items,
        }
    }
}

impl Display for ActionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Archive ID: {}, Actions: {}",
            self.archive_id,
            self.actions.len()
        )?;
        for item in self.actions.iter() {
            write!(f, "\n{item}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie(u64);

impl Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl From<Cookie> for u64 {
    fn from(cookie: Cookie) -> u64 {
        cookie.0
    }
}

impl From<u64> for Cookie {
    fn from(cookie: u64) -> Self {
        Cookie(cookie)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionItem {
    pub action: CopytoolAction,
    pub fid: Fid,
    pub dfid: Fid,
    pub extent: Extent,
    pub cookie: Cookie,
    pub gid: u64,
    pub data: Vec<u8>,
}

unsafe impl Send for ActionItem {}

impl From<&hsm_action_item> for ActionItem {
    fn from(hai: &hsm_action_item) -> Self {
        let len: usize = hai.hai_len as usize - size_of::<hsm_action_item>();

        let data = unsafe { hai.hai_data.as_slice(len) };
        Self {
            action: CopytoolAction::from(hai.hai_action),
            fid: Fid::from(hai.hai_fid),
            dfid: Fid::from(hai.hai_dfid),
            extent: Extent {
                offset: hai.hai_extent.offset,
                length: hai.hai_extent.length,
            },
            cookie: hai.hai_cookie.into(),
            gid: hai.hai_gid,
            #[allow(clippy::unnecessary_cast)] // only an issue on arm64
            data: data.iter().map(|c| *c as u8).collect(),
        }
    }
}

impl ActionItem {
    pub fn to_native(&self) -> Box<hsm_action_item> {
        let mut hai = Box::new(hsm_action_item::default());
        hai.hai_len = size_of::<hsm_action_item>() as u32; // + (self.data.len() as u32);
        hai.hai_action = self.action.clone() as u32;
        hai.hai_fid = self.fid.to_lu_fid();
        hai.hai_dfid = self.dfid.to_lu_fid();
        hai.hai_extent.offset = self.extent.offset;
        hai.hai_extent.length = self.extent.length;
        hai.hai_cookie = self.cookie.0;
        hai.hai_gid = self.gid;

        // Not clear where to free this memory, so disabled for now.
        // Also don't think the data field needs to be sent back to the
        // coordinator since it appears to be for the copytool's use.
        //
        // if !self.data.is_empty() {
        //     let layout =
        //         Layout::from_size_align(self.data.len(), mem::align_of::<c_char>()).unwrap();
        //     let ptr = unsafe { alloc(layout) };
        //     unsafe {
        //         std::ptr::copy(self.data.as_ptr(), ptr, self.data.len());
        //     }
        //     hai.hai_data = ptr as *mut c_char;
        // }

        hai
    }
}

impl Display for ActionItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "action: {:?} {}, extent: {}, cookie: {}, gid: {}",
            self.action, self.fid, self.extent, self.cookie, self.gid
        )?;
        if self.fid != self.dfid {
            write!(f, ", Dfid:  {}", self.dfid)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u32)]
pub enum CopytoolAction {
    None = HSMA_NONE,
    Archive = HSMA_ARCHIVE,
    Restore = HSMA_RESTORE,
    Cancel = HSMA_CANCEL,
    Remove = HSMA_REMOVE,
}

impl From<u32> for CopytoolAction {
    fn from(value: u32) -> Self {
        match value {
            HSMA_NONE => CopytoolAction::None,
            HSMA_ARCHIVE => CopytoolAction::Archive,
            HSMA_RESTORE => CopytoolAction::Restore,
            HSMA_CANCEL => CopytoolAction::Cancel,
            HSMA_REMOVE => CopytoolAction::Remove,
            _ => panic!("Invalid CopytoolAction"),
        }
    }
}
impl Display for CopytoolAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extent {
    pub offset: u64,
    pub length: u64,
}

impl Default for Extent {
    fn default() -> Self {
        Self {
            offset: 0,
            length: LUSTRE_EOF as u64,
        }
    }
}
impl From<Extent> for hsm_extent {
    fn from(extent: Extent) -> Self {
        Self {
            offset: extent.offset,
            length: extent.length,
        }
    }
}

impl From<hsm_extent> for Extent {
    fn from(extent: hsm_extent) -> Self {
        Self {
            offset: extent.offset,
            length: extent.length,
        }
    }
}

impl Display for Extent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.offset, self.length as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_action_list_new() {
        let hal = hsm_action_list::default();
        let layout = Layout::array::<hsm_action_list>(1).expect("Layout should be valid.");
        assert!(layout.size() > 0);
        let al = ActionList::new(&hal, layout.size());
        drop(al);
    }
}
