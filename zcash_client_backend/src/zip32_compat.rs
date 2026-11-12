//! Converts between the two `zip32` versions in the dependency graph.
//!
//! `sapling-crypto` 0.8 moved to `zip32` 0.3 while Orchard 0.15 and this crate are still on
//! 0.2. The shared items are plain data - a two-variant enum and an integer newtype - so each
//! one converts by value rather than needing a wrapper.
//!
//! TODO: Delete this module once orchard 0.16 removes the second zip32 major.

/// Converts a key scope to the version `sapling-crypto` expects.
pub(crate) fn scope_03(scope: zip32::Scope) -> zip32_03::Scope {
    match scope {
        zip32::Scope::External => zip32_03::Scope::External,
        zip32::Scope::Internal => zip32_03::Scope::Internal,
    }
}

/// Converts a diversifier index to the version `sapling-crypto` expects.
#[cfg(any(test, feature = "test-dependencies"))]
pub(crate) fn diversifier_index_03(j: zip32::DiversifierIndex) -> zip32_03::DiversifierIndex {
    zip32_03::DiversifierIndex::from(*j.as_bytes())
}
