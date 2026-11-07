//! Bridges this crate's `rand_core` 0.6 RNGs to the `rand_core` 0.10 API.
//!
//! Sapling moved to `rand_core` 0.10 in `sapling-crypto` 0.8, while Orchard 0.15 and this
//! workspace are still on 0.6. The two crates' RNG traits only ever appear as bounds on
//! function parameters, never in a type that is stored or returned, so a wrapper at each
//! call boundary is enough.
//!
//! TODO: Remove once the workspace moves to `rand` 0.10.

use core::convert::Infallible;

use rand_core::{CryptoRng, RngCore};

/// Adapts a `rand_core` 0.6 RNG to the `rand_core` 0.10 API.
///
/// `rand_core` 0.10 blanket-implements its `Rng` for any `TryRng<Error = Infallible>`, so
/// implementing `TryRng` is enough to satisfy an `R: Rng` bound. The byte stream is
/// unchanged: every method forwards to the wrapped RNG.
pub struct Rng010<R>(pub R);

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

/// The cryptographic marker is only asserted when the wrapped RNG carries it.
impl<R: RngCore + CryptoRng> rand_core_010::TryCryptoRng for Rng010<R> {}
