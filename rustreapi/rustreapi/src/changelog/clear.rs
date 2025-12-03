// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

use std::ffi::CString;

use super::error::{ChangelogError, Result as ChangelogResult};
use crate::error::cvt_rc_m;
use changelog_sys::llapi_changelog_clear;

/// Clear changelog records up to a specific record index for a given MDT and consumer.
///
/// This function wraps the `llapi_changelog_clear` function to safely clear processed
/// changelog records, allowing the Lustre filesystem to reclaim space used by old
/// changelog entries.
///
/// # Arguments
/// * `mdt_name` - The MDT device name (e.g., "lustre-MDT0000")
/// * `consumer_id` - The changelog consumer identifier (e.g., `"cl1"`)
/// * `end_record` - The highest record index to clear (inclusive)
///
/// # Returns
/// * `Ok(())` if the clear operation succeeded
/// * `Err(ChangelogError)` if the operation failed
///
/// # Examples
/// ```rust,no_run
/// use rustreapi::changelog::changelog_clear;
///
/// // Clear records up to index 1000 for consumer "cl1" on MDT0000
/// changelog_clear("lustre-MDT0000", "cl1", 1000)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Safety
/// This function is safe to call, but the underlying Lustre API requires:
/// - The MDT name must be valid and accessible
/// - The consumer ID must exist and be registered with the MDT
/// - The caller must have appropriate permissions to clear changelog records
pub fn changelog_clear(mdt_name: &str, consumer_id: &str, end_record: u64) -> ChangelogResult<()> {
    let mdt_cstring = CString::new(mdt_name).map_err(|e| ChangelogError::InvalidMdtName {
        mdt_name: mdt_name.to_string(),
        source: Box::new(e),
    })?;

    let consumer_cstring =
        CString::new(consumer_id).map_err(|e| ChangelogError::InvalidConsumerId {
            consumer_id: consumer_id.to_string(),
            source: Box::new(e),
        })?;

    // TODO check for overflow `(end_record as i64) < 0`
    let rc = unsafe {
        llapi_changelog_clear(
            mdt_cstring.as_ptr(),
            consumer_cstring.as_ptr(),
            end_record as i64,
        )
    };

    cvt_rc_m(
        rc,
        format!(
            "Failed to clear changelog records for MDT {} consumer {} up to record {}",
            mdt_name, consumer_id, end_record
        ),
    )
    .map_err(|e| ChangelogError::ClearFailed {
        mdt_name: mdt_name.to_string(),
        consumer_id: consumer_id.to_string(),
        end_record,
        source: Box::new(e),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_changelog_clear_invalid_names() {
        // Test with null bytes in strings
        assert!(changelog_clear("test\0mdt", "cl1", 100).is_err());
        assert!(changelog_clear("test-mdt", "cl\x01", 100).is_err());
    }

    #[test]
    fn test_changelog_clear_parameters() {
        // These will fail in practice but should not panic
        let result = changelog_clear("nonexistent-MDT0000", "cl999", 0);
        assert!(result.is_err());
    }
}
