//! Sighash versioning as specified in [ZIP-246].
//!
//! [ZIP-246]: https://zips.z.cash/zip-0246

use alloc::{collections::BTreeMap, vec::Vec};
use lazy_static::lazy_static;

use orchard::{
    issuance_sighash_versioning::IssueSighashVersion,
    orchard_sighash_versioning::OrchardSighashVersion,
};

/// The sighash version and associated data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SighashInfo {
    version: u8,
    associated_data: Vec<u8>,
}

impl SighashInfo {
    /// Constructs a `SighashInfo` from raw bytes.
    ///
    /// Returns `None` if `bytes` is empty.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.split_first().map(|(&version, info)| Self {
            version,
            associated_data: info.to_vec(),
        })
    }

    /// Returns the raw bytes of the `SighashInfo`.
    pub fn to_bytes(&self) -> Vec<u8> {
        [vec![self.version], self.associated_data.clone()].concat()
    }

    #[cfg(zcash_unstable = "nu7")]
    pub(crate) fn to_orchard_version(&self) -> Option<OrchardSighashVersion> {
        ORCHARD_SIGHASH_VERSION_TO_INFO
            .iter()
            .find(|(_, v)| *v == self)
            .map(|(k, _)| k.clone())
    }

    pub(crate) fn to_issuance_version(&self) -> Option<IssueSighashVersion> {
        ISSUE_SIGHASH_VERSION_TO_INFO
            .iter()
            .find(|(_, v)| *v == self)
            .map(|(k, _)| k.clone())
    }
}

lazy_static! {
    pub(crate) static ref ORCHARD_SIGHASH_VERSION_TO_INFO: BTreeMap<OrchardSighashVersion, SighashInfo> = {
        let mut map: BTreeMap<OrchardSighashVersion, SighashInfo> = BTreeMap::new();
        map.insert(
            OrchardSighashVersion::V0,
            SighashInfo {
                version: 0,
                associated_data: vec![],
            },
        );
        map
    };
}
lazy_static! {
    pub(crate) static ref ISSUE_SIGHASH_VERSION_TO_INFO: BTreeMap<IssueSighashVersion, SighashInfo> = {
        let mut map: BTreeMap<IssueSighashVersion, SighashInfo> = BTreeMap::new();
        map.insert(
            IssueSighashVersion::V0,
            SighashInfo {
                version: 0,
                associated_data: vec![],
            },
        );
        map
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sighash_version_encoding_roundtrip() {
        let bytes: [u8; 10] = [2u8; 10];
        let sighash_info = SighashInfo::from_bytes(&bytes).unwrap();
        assert_eq!(bytes[0], sighash_info.version);
        assert_eq!(bytes[1..], sighash_info.associated_data);

        let sighash_info_bytes = sighash_info.to_bytes();
        assert_eq!(bytes, sighash_info_bytes.as_slice());
    }
}
