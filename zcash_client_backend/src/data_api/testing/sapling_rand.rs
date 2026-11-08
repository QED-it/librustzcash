//! A random-frontier helper for Sapling that works across the two `rand` versions.
//!
//! `incrementalmerkletree` 0.8's `Frontier::random_with_prior_subtree_roots` requires
//! `rand` 0.8's `Standard: Distribution<H>`, but `sapling-crypto` 0.8 only provides the
//! `rand` 0.10 `StandardUniform` impl for `Node`. The orphan rule forbids writing the
//! missing impl here, so the frontier is generated for a local newtype and converted.
//!
//! TODO: Delete this helper once orchard 0.16 makes the upstream one usable again.

use core::num::NonZeroU8;

use group::ff::Field;
use incrementalmerkletree::{Hashable, Level, frontier::Frontier};
use rand::{
    Rng,
    distributions::{Distribution, Standard},
};
use rand_core::RngCore;
use sapling::Node;
use zcash_primitives::rand_compat::Rng010;

/// A `Node` that `rand` 0.8 can sample.
#[derive(Clone, Copy, Debug)]
struct RandNode(Node);

impl Hashable for RandNode {
    fn empty_leaf() -> Self {
        RandNode(Node::empty_leaf())
    }

    fn combine(level: Level, lhs: &Self, rhs: &Self) -> Self {
        RandNode(Node::combine(level, &lhs.0, &rhs.0))
    }

    fn empty_root(level: Level) -> Self {
        RandNode(Node::empty_root(level))
    }
}

impl Distribution<RandNode> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RandNode {
        // Mirrors `sapling_crypto`'s own impl, through the `rand_core` 0.10 bridge.
        RandNode(Node::from_scalar(bls12_381::Scalar::random(&mut Rng010(
            rng,
        ))))
    }
}

/// `Frontier::random_with_prior_subtree_roots` for Sapling.
pub fn random_sapling_frontier_with_prior_subtree_roots<R: RngCore, const DEPTH: u8>(
    rng: &mut R,
    tree_size: u64,
    subtree_depth: NonZeroU8,
) -> (Vec<Node>, Frontier<Node, DEPTH>) {
    let (roots, frontier) =
        Frontier::<RandNode, DEPTH>::random_with_prior_subtree_roots(rng, tree_size, subtree_depth);

    let frontier = match frontier.take() {
        None => Frontier::empty(),
        Some(nonempty) => {
            let (position, leaf, ommers) = nonempty.into_parts();
            Frontier::from_parts(
                position,
                leaf.0,
                ommers.into_iter().map(|node| node.0).collect(),
            )
            .expect("the frontier was built by incrementalmerkletree itself")
        }
    };

    (roots.into_iter().map(|node| node.0).collect(), frontier)
}
