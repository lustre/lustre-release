// SPDX-License-Identifier: MIT

// Copyright (c) 2025 DDN. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

mod builder;
mod clear;
mod convert;
mod error;
mod flags;
mod reader;
mod record;
#[cfg(test)]
mod tests;

pub use builder::ChangelogBuilder;
pub use clear::changelog_clear;
pub use convert::{
    ChangelogRecord, ClientNid, ConvertRecord, RecordConverter, RecordConverterBuilder, TimeFormat,
};
pub use error::{ChangelogError, Result as ChangelogResult};
pub use flags::{ChangelogExtraFlag, ChangelogFlag};
pub use reader::ChangelogReader;
pub use record::{Record, RecordType};
