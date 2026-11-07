//! Bridges this crate's `rand_core` 0.6 RNGs to the `rand_core` 0.10 API.
//!
//! See `zcash_primitives::rand_compat`; this crate carries its own copy because the roles
//! that need it are enabled by features that do not pull in `zcash_primitives`.
//!
//! TODO: Remove once the workspace moves to `rand` 0.10.

use core::convert::Infallible;

use rand_core::{CryptoRng, RngCore};

/// Adapts a `rand_core` 0.6 RNG to the `rand_core` 0.10 API.
pub(crate) struct Rng010<R>(pub R);

impl<R: RngCore> rand_core_010::TryRng for Rng010<R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<R: RngCore + CryptoRng> rand_core_010::TryCryptoRng for Rng010<R> {}
