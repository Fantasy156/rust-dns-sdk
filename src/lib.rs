//! DNS SDK for multi-cloud provider integration
//!
//! Supported features:
//! - Unified API for multiple DNS providers
//! - Asynchronous operations
//! - Builder pattern for request configuration
//!
//! # Example
//! ```
//! use rust_dns_sdk::client::{DnsProvider, DnsProviderImpl, RecordOperationBuilder};
//!
//! let client = DnsProviderImpl::new(DnsProvider::Tencent)
//!     .set_param("secret_id", "your_id")
//!     .set_param("secret_key", "your_key")
//!     .build();
//! ```

// Copyright 2023 rust-dns-sdk authors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pub(crate) mod providers;
pub mod client;