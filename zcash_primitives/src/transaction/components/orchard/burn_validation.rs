use std::fmt;

use orchard::note::AssetBase;

use super::Amount;

// FIXME: Consider making tuple (AssetBase, Amount) a new type.

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum BurnError {
    DuplicateAsset,
    NativeAsset,
    ZeroAmount,
}

impl fmt::Display for BurnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BurnError::DuplicateAsset => write!(f, "Encountered a duplicate asset to burn."),
            BurnError::NativeAsset => write!(f, "Cannot burn a native asset."),
            BurnError::ZeroAmount => write!(f, "Cannot burn an asset with a zero amount."),
        }
    }
}

/// Validates burns for a bundle by ensuring each asset is unique, non-native, and has a non-zero value.
///
/// Each burn element is represented as a tuple of `AssetBase` and `Amount`, where `AssetBase` identifies
/// the asset to be burned and `Amount` is the quantity to burn.
///
/// # Arguments
///
/// * `burns` - A vector of burns, where each burn is represented as a tuple of `AssetBase` and `Amount`.
///
/// # Errors
///
/// Returns a `BurnError` if:
/// * Any asset in the list of burns is not unique (`BurnError::DuplicateAsset`).
/// * Any asset in the list of burns is native (`BurnError::NativeAsset`).
/// * Any asset in the list of burns has a zero amount (`BurnError::ZeroAmount`).
pub fn validate_bundle_burn(bundle_burn: &Vec<(AssetBase, Amount)>) -> Result<(), BurnError> {
    let mut asset_set = std::collections::HashSet::<AssetBase>::new();

    for (asset, amount) in bundle_burn {
        if !asset_set.insert(*asset) {
            return Err(BurnError::DuplicateAsset);
        }
        if asset.is_native().into() {
            return Err(BurnError::NativeAsset);
        }
        // FIXME: check for negative amounts?
        if i64::from(amount) == 0 {
            return Err(BurnError::ZeroAmount);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::transaction::tests::create_test_asset;

    #[test]
    fn test_validate_bundle_burn_success() {
        let bundle_burn = vec![
            (create_test_asset("Asset 1"), Amount::from_u64(10).unwrap()),
            (create_test_asset("Asset 2"), Amount::from_u64(20).unwrap()),
            (create_test_asset("Asset 3"), Amount::from_u64(10).unwrap()),
        ];

        let result = validate_bundle_burn(&bundle_burn);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_bundle_burn_duplicate_asset() {
        let bundle_burn = vec![
            (create_test_asset("Asset 1"), Amount::from_u64(10).unwrap()),
            (create_test_asset("Asset 1"), Amount::from_u64(20).unwrap()),
            (create_test_asset("Asset 3"), Amount::from_u64(10).unwrap()),
        ];

        let result = validate_bundle_burn(&bundle_burn);

        assert_eq!(result, Err(BurnError::DuplicateAsset));
    }

    #[test]
    fn test_validate_bundle_burn_native_asset() {
        let bundle_burn = vec![
            (create_test_asset("Asset 1"), Amount::from_u64(10).unwrap()),
            (AssetBase::native(), Amount::from_u64(20).unwrap()),
            (create_test_asset("Asset 3"), Amount::from_u64(10).unwrap()),
        ];

        let result = validate_bundle_burn(&bundle_burn);

        assert_eq!(result, Err(BurnError::NativeAsset));
    }

    #[test]
    fn test_validate_bundle_burn_zero_amount() {
        let bundle_burn = vec![
            (create_test_asset("Asset 1"), Amount::from_u64(10).unwrap()),
            (create_test_asset("Asset 2"), Amount::from_u64(0).unwrap()),
            (create_test_asset("Asset 3"), Amount::from_u64(10).unwrap()),
        ];

        let result = validate_bundle_burn(&bundle_burn);

        assert_eq!(result, Err(BurnError::ZeroAmount));
    }
}
