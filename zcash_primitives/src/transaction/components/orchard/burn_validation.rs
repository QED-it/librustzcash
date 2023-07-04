use std::fmt;

use orchard::note::AssetBase;

use super::Amount;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum BurnError {
    DuplicateAsset,
    NativeAsset,
    NonPositiveAmount,
}

impl fmt::Display for BurnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BurnError::DuplicateAsset => write!(f, "Encountered a duplicate asset to burn."),
            BurnError::NativeAsset => write!(f, "Cannot burn a native asset."),
            BurnError::NonPositiveAmount => {
                write!(f, "Cannot burn an asset with a nonpositive amount.")
            }
        }
    }
}

/// Validates burn for a bundle by ensuring each asset is unique, non-native, and has a positive value.
///
/// Each burn element is represented as a tuple of `AssetBase` and `Amount`.
///
/// # Arguments
///
/// * `burn` - A vector of assets, where each asset is represented as a tuple of `AssetBase` and `Amount`.
///
/// # Errors
///
/// Returns a `BurnError` if:
/// * Any asset in the `burn` vector is not unique (`BurnError::DuplicateAsset`).
/// * Any asset in the `burn` vector is native (`BurnError::NativeAsset`).
/// * Any asset in the `burn` vector has a nonpositive amount (`BurnError::NonPositiveAmount`).
pub fn validate_bundle_burn(bundle_burn: &Vec<(AssetBase, Amount)>) -> Result<(), BurnError> {
    let mut asset_set = std::collections::HashSet::<AssetBase>::new();

    for (asset, amount) in bundle_burn {
        if !asset_set.insert(*asset) {
            return Err(BurnError::DuplicateAsset);
        }
        if asset.is_native().into() {
            return Err(BurnError::NativeAsset);
        }
        if i64::from(amount) <= 0 {
            return Err(BurnError::NonPositiveAmount);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::transaction::tests::get_burn_tuple;

    #[test]
    fn validate_bundle_burn_success() {
        let bundle_burn = vec![
            get_burn_tuple("Asset 1", 10),
            get_burn_tuple("Asset 2", 20),
            get_burn_tuple("Asset 3", 10),
        ];

        let result = validate_bundle_burn(&bundle_burn);

        assert!(result.is_ok());
    }

    #[test]
    fn validate_bundle_burn_duplicate_asset() {
        let bundle_burn = vec![
            get_burn_tuple("Asset 1", 10),
            get_burn_tuple("Asset 1", 20),
            get_burn_tuple("Asset 3", 10),
        ];

        let result = validate_bundle_burn(&bundle_burn);

        assert_eq!(result, Err(BurnError::DuplicateAsset));
    }

    #[test]
    fn validate_bundle_burn_native_asset() {
        let bundle_burn = vec![
            get_burn_tuple("Asset 1", 10),
            (AssetBase::native(), Amount::from_u64(20).unwrap()),
            get_burn_tuple("Asset 3", 10),
        ];

        let result = validate_bundle_burn(&bundle_burn);

        assert_eq!(result, Err(BurnError::NativeAsset));
    }

    #[test]
    fn validate_bundle_burn_zero_amount() {
        let bundle_burn = vec![
            get_burn_tuple("Asset 1", 10),
            get_burn_tuple("Asset 2", 0),
            get_burn_tuple("Asset 3", 10),
        ];

        let result = validate_bundle_burn(&bundle_burn);

        assert_eq!(result, Err(BurnError::NonPositiveAmount));
    }
}
