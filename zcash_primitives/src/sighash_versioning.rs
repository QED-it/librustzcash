//! Sighash versioning as specified in [ZIP-246].
//!
//! [ZIP-246]: https://zips.z.cash/zip-0246

use alloc::{collections::BTreeMap, vec::Vec};
use lazy_static::lazy_static;

use orchard::orchard_sighash_versioning::OrchardSighashVersion;

#[cfg(zcash_unstable = "nu7")]
use orchard::issuance_sighash_versioning::IssueSighashVersion;

lazy_static! {
    pub(crate) static ref ORCHARD_SIGHASH_VERSION_TO_BYTES: BTreeMap<OrchardSighashVersion, Vec<u8>> =
        BTreeMap::from([(OrchardSighashVersion::V0, vec![0],)]);
}

#[cfg(zcash_unstable = "nu7")]
pub(crate) fn to_orchard_version(bytes: Vec<u8>) -> Option<OrchardSighashVersion> {
    ORCHARD_SIGHASH_VERSION_TO_BYTES
        .iter()
        .find(|(_, v)| **v == bytes)
        .map(|(k, _)| k.clone())
}

#[cfg(zcash_unstable = "nu7")]
lazy_static! {
    pub(crate) static ref ISSUE_SIGHASH_VERSION_TO_BYTES: BTreeMap<IssueSighashVersion, Vec<u8>> =
        BTreeMap::from([(IssueSighashVersion::V0, vec![0],)]);
}

#[cfg(zcash_unstable = "nu7")]
pub(crate) fn to_issuance_version(bytes: Vec<u8>) -> Option<IssueSighashVersion> {
    ISSUE_SIGHASH_VERSION_TO_BYTES
        .iter()
        .find(|(_, v)| **v == bytes)
        .map(|(k, _)| k.clone())
}
