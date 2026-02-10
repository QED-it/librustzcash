//! Wallet storage abstractions for transparent address gap limit management.
//!
//! This module defines the [`GapLimitsWalletAccess`] trait, which provides the storage
//! operations needed by the gap limit address generation logic in
//! [`super::gap_limits::wallet`].

use crate::address::Address;
use core::hash::Hash;
use std::vec::Vec;
use transparent::{
    address::TransparentAddress,
    keys::{NonHardenedChildIndex, TransparentKeyScope},
};

/// A trait providing wallet storage operations required for transparent address gap limit
/// management.
///
/// Implementations of this trait allow the gap limit logic in
/// [`gap_limits::wallet`](super::gap_limits::wallet) to query and update the wallet's
/// transparent address state without being coupled to a specific storage backend.
#[cfg(feature = "transparent-inputs")]
pub trait GapLimitsWalletAccess {
    /// The type of errors produced by the wallet storage backend.
    type Error;

    /// A wallet-internal account identifier.
    type AccountRef: Copy + Eq + Hash;

    /// Returns the transparent address index at the start of the first gap of at least `gap_limit`
    /// indices in the given account, considering only addresses derived for the specified key scope.
    ///
    /// Returns `Ok(None)` if the gap would start at an index greater than the maximum valid
    /// non-hardened transparent child index.
    fn find_gap_start(
        &self,
        account_ref: Self::AccountRef,
        key_scope: TransparentKeyScope,
        gap_limit: u32,
    ) -> Result<Option<NonHardenedChildIndex>, Self::Error>;

    /// Persists a range of derived transparent addresses to the wallet storage.
    ///
    /// Each entry in the list contains the wallet-level address, the raw transparent address,
    /// and the child index from which the address was derived.
    fn store_address_range(
        &mut self,
        account_id: Self::AccountRef,
        key_scope: TransparentKeyScope,
        list: Vec<(Address, TransparentAddress, NonHardenedChildIndex)>,
    ) -> Result<(), Self::Error>;
}
