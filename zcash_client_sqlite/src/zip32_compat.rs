//! Converts between the two `zip32` versions in the dependency graph.
//!
//! `sapling-crypto` 0.8 moved to `zip32` 0.3 while Orchard 0.15 and this crate are still on
//! 0.2, and `sapling-crypto`'s diversifier indices come back in the newer type.
//!
//! TODO: Remove once the workspace moves to `zip32` 0.3.

/// Converts a diversifier index back from the version `sapling-crypto` returns.
pub(crate) fn diversifier_index_02(j: zip32_03::DiversifierIndex) -> zip32::DiversifierIndex {
    zip32::DiversifierIndex::from(*j.as_bytes())
}
