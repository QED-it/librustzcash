//! *General Zcash primitives.*
//!
//! `zcash_primitives` is a library that provides the core structs and functions necessary
//! for working with Zcash.
//!
//! ## Feature flags
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// Present to reduce refactoring noise from changing all the imports inside this crate for
// the `sapling` crate extraction.
#![allow(clippy::single_component_path_imports)]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
extern crate alloc;

pub mod block;
pub(crate) mod encoding;
pub mod merkle_tree;
// Not part of the public API: a version bridge that exists only while the workspace carries
// two `rand_core` majors. `zcash_proofs`, `zcash_client_backend` and `pczt` need it.
// TODO: Remove this declaration along with the module when orchard 0.16 lands.
#[doc(hidden)]
pub mod rand_compat;
pub mod sighash_versioning;
pub mod transaction;
