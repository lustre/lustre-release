// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use crate::RecordType;
use thiserror::Error;

/// Errors that can occur during changelog operations.
#[derive(Error, Debug)]
pub enum ChangelogError {
    /// A record is missing its target FID when one is required.
    #[error("{record_type} record is missing required target FID")]
    MissingTargetFid {
        /// The type of record that was missing the target FID
        record_type: RecordType,
    },

    /// A record type is not supported by the converter.
    #[error("unsupported changelog record type: {record_type}")]
    UnsupportedRecordType {
        /// The unsupported record type
        record_type: RecordType,
    },

    /// Invalid time format encountered during time conversion.
    #[error("invalid time format for timestamp: {timestamp}")]
    InvalidTimeFormat {
        /// The raw timestamp value that could not be converted
        timestamp: u64,
    },

    /// A changelog record pointer is null or invalid.
    #[error("changelog record pointer is null or invalid")]
    InvalidRecordPointer,

    /// Failed to receive changelog record from device.
    #[error("failed to receive changelog record from device {device}")]
    ReceiveFailed {
        /// The device that failed to provide records
        device: String,
        /// The underlying error that caused the receive to fail
        #[source]
        source: Box<crate::Error>,
    },

    /// Failed to establish connection to changelog.
    #[error("failed to connect to changelog for device {device}")]
    ConnectionFailed {
        /// The device that failed to connect
        device: String,
        /// The underlying I/O error that caused the connection to fail
        #[source]
        source: std::io::Error,
    },

    /// Device name was not specified when required.
    #[error("device name must be specified")]
    MissingDevice,

    /// Invalid device name contains null bytes.
    #[error("device name contains null bytes: {device}: {source}")]
    InvalidDevice {
        /// The invalid device name that was provided
        device: String,
        /// The underlying `NulError`
        #[source]
        source: std::ffi::NulError,
    },

    /// Failed to start changelog connection.
    #[error("failed to start changelog for device {device}")]
    StartFailed {
        /// The device that failed to start
        device: String,
        /// The underlying error that caused the start to fail
        #[source]
        source: Box<crate::Error>,
    },

    /// `llapi_changelog_start` returned null pointer.
    #[error("llapi_changelog_start returned null pointer for device {device}")]
    StartInvalidResult {
        /// The device that returned null pointer
        device: String,
    },

    /// Failed to set extra flags for changelog.
    #[error("failed to set extra flags for device {device}")]
    SetExtraFlagsFailed {
        /// The device that failed to set extra flags
        device: String,
        /// The underlying error that caused setting extra flags to fail
        #[source]
        source: Box<crate::Error>,
    },

    /// Invalid MDT name contains null bytes.
    #[error("MDT name contains null bytes: {mdt_name}: {source}")]
    InvalidMdtName {
        /// The invalid MDT name that was provided
        mdt_name: String,
        /// The underlying `NulError`
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Invalid consumer ID contains null bytes.
    #[error("consumer ID contains null bytes: {consumer_id}: {source}")]
    InvalidConsumerId {
        /// The invalid consumer ID that was provided
        consumer_id: String,
        /// The underlying `NulError`
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Failed to clear changelog records.
    #[error(
        "failed to clear changelog records for MDT {mdt_name} consumer {consumer_id} up to record {end_record}"
    )]
    ClearFailed {
        /// The MDT name that failed to clear
        mdt_name: String,
        /// The consumer ID that failed to clear
        consumer_id: String,
        /// The end record index that was attempted
        end_record: u64,
        /// The underlying error that caused the clear to fail
        #[source]
        source: Box<crate::Error>,
    },
}

/// Result type for changelog operations.
pub type Result<T> = std::result::Result<T, ChangelogError>;
