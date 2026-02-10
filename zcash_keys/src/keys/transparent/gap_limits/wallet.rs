//! Wallet-specific operations for transparent address gap limit management.
//!
//! This module provides functions for generating transparent addresses according to BIP-44
//! gap limit rules, abstracting over the wallet storage backend via the
//! [`GapLimitsWalletAccess`] trait.

use super::GapLimits;
use crate::address::Address;
use crate::keys::{
    AddressGenerationError, UnifiedAddressRequest, transparent::wallet::GapLimitsWalletAccess,
};
use crate::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use core::ops::Range;
use std::vec::Vec;
use transparent::address::TransparentAddress;
use transparent::keys::{
    IncomingViewingKey, NonHardenedChildIndex, NonHardenedChildRange, TransparentKeyScope,
};
use zcash_address::unified::Typecode;
use zip32::DiversifierIndex;

fn generate_external_address(
    uivk: &UnifiedIncomingViewingKey,
    ua_request: UnifiedAddressRequest,
    index: NonHardenedChildIndex,
) -> Result<(Address, TransparentAddress), AddressGenerationError> {
    let ua = uivk.address(index.into(), ua_request);
    let transparent_address = uivk
        .transparent()
        .as_ref()
        .ok_or(AddressGenerationError::KeyNotAvailable(Typecode::P2pkh))?
        .derive_address(index)
        .map_err(|_| {
            AddressGenerationError::InvalidTransparentChildIndex(DiversifierIndex::from(index))
        })?;
    Ok((
        ua.map_or_else(
            |e| {
                if matches!(e, AddressGenerationError::ShieldedReceiverRequired) {
                    // fall back to the transparent-only address
                    Ok(Address::from(transparent_address))
                } else {
                    // other address generation errors are allowed to propagate
                    Err(e)
                }
            },
            |addr| Ok(Address::from(addr)),
        )?,
        transparent_address,
    ))
}

/// Generates a list of addresses for the given range of transparent child indices.
///
/// For external-scoped addresses, a unified address is generated using the provided
/// [`UnifiedAddressRequest`]; for internal and ephemeral scopes, the raw transparent address is
/// returned.
///
/// Returns an empty list if the account lacks a transparent key and `require_key` is `false`.
/// Returns an error if the key is required but unavailable, or if the key scope is unsupported.
pub fn generate_address_list(
    account_uivk: &UnifiedIncomingViewingKey,
    account_ufvk: Option<&UnifiedFullViewingKey>,
    key_scope: TransparentKeyScope,
    request: UnifiedAddressRequest,
    range_to_store: Range<NonHardenedChildIndex>,
    require_key: bool,
) -> Result<Vec<(Address, TransparentAddress, NonHardenedChildIndex)>, AddressGenerationError> {
    let account_pubkey = if let Some(k) = account_ufvk.and_then(|ufvk| ufvk.transparent()) {
        k
    } else if matches!(
        key_scope,
        TransparentKeyScope::INTERNAL | TransparentKeyScope::EPHEMERAL
    ) && require_key
    {
        return Err(AddressGenerationError::KeyNotAvailable(Typecode::P2pkh));
    } else {
        // No addresses to generate
        return Ok(vec![]);
    };

    let gen_addrs = |key_scope: TransparentKeyScope, index: NonHardenedChildIndex| match key_scope {
        TransparentKeyScope::EXTERNAL => generate_external_address(account_uivk, request, index),
        TransparentKeyScope::INTERNAL => {
            let internal_address = account_pubkey
                .derive_internal_ivk()?
                .derive_address(index)?;
            Ok((Address::from(internal_address), internal_address))
        }
        TransparentKeyScope::EPHEMERAL => {
            let ephemeral_address = account_pubkey
                .derive_ephemeral_ivk()?
                .derive_ephemeral_address(index)?;
            Ok((Address::from(ephemeral_address), ephemeral_address))
        }
        _ => Err(AddressGenerationError::UnsupportedTransparentKeyScope(
            key_scope,
        )),
    };

    NonHardenedChildRange::from(range_to_store)
        .into_iter()
        .map(|transparent_child_index| {
            let (address, transparent_address) = gen_addrs(key_scope, transparent_child_index)?;
            Ok((address, transparent_address, transparent_child_index))
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Errors that can occur when generating transparent gap addresses.
pub enum GapAddressesError<SE> {
    /// An error occurred in the underlying wallet storage backend.
    Storage(SE),
    /// An error occurred while deriving a transparent address.
    AddressGeneration(AddressGenerationError),
    /// The specified account was not found in the wallet database.
    AccountUnknown,
}

/// Generates transparent addresses to fill the gap for a given account and key scope.
///
/// This function queries the wallet backend (via [`GapLimitsWalletAccess`]) to find the start
/// of the first gap of unused addresses, then generates enough addresses to maintain the
/// configured gap limit. If no gap exists (i.e., the address space is exhausted), this is a
/// no-op.
#[allow(clippy::too_many_arguments)]
pub fn generate_gap_addresses<DbT, SE>(
    wallet_db: &mut DbT,
    gap_limits: &GapLimits,
    account_id: DbT::AccountRef,
    account_uivk: &UnifiedIncomingViewingKey,
    account_ufvk: Option<&UnifiedFullViewingKey>,
    key_scope: TransparentKeyScope,
    request: UnifiedAddressRequest,
    require_key: bool,
) -> Result<(), GapAddressesError<SE>>
where
    DbT: GapLimitsWalletAccess<Error = SE>,
{
    let gap_limit = gap_limits
        .limit_for(key_scope)
        .ok_or(GapAddressesError::AddressGeneration(
            AddressGenerationError::UnsupportedTransparentKeyScope(key_scope),
        ))?;

    if let Some(gap_start) = wallet_db
        .find_gap_start(account_id, key_scope, gap_limit)
        .map_err(GapAddressesError::Storage)?
    {
        let address_list = generate_address_list(
            account_uivk,
            account_ufvk,
            key_scope,
            request,
            gap_start..gap_start.saturating_add(gap_limit),
            require_key,
        )
        .map_err(GapAddressesError::AddressGeneration)?;
        wallet_db
            .store_address_range(account_id, key_scope, address_list)
            .map_err(GapAddressesError::Storage)?;
    }

    Ok(())
}
