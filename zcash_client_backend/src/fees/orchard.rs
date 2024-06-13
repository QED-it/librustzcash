//! Types related to computation of fees and change related to the Orchard components
//! of a transaction.

use std::convert::Infallible;
use zcash_primitives::transaction::components::amount::NonNegativeAmount;

use orchard::builder::BundleType;

/// A trait that provides a minimized view of Orchard bundle configuration
/// suitable for use in fee and change calculation.
pub trait BundleView<NoteRef> {
    /// The type of inputs to the bundle.
    type In: InputView<NoteRef>;
    /// The type of inputs of the bundle.
    type Out: OutputView;

    /// Returns the type of the bundle
    fn bundle_type(&self) -> BundleType;
    /// Returns the inputs to the bundle.
    fn inputs(&self) -> &[Self::In];
    /// Returns the outputs of the bundle.
    fn outputs(&self) -> &[Self::Out];
}

impl<'a, NoteRef, In: InputView<NoteRef>, Out: OutputView> BundleView<NoteRef>
    for (BundleType, &'a [In], &'a [Out])
{
    type In = In;
    type Out = Out;

    fn bundle_type(&self) -> BundleType {
        self.0
    }

    fn inputs(&self) -> &[In] {
        self.1
    }

    fn outputs(&self) -> &[Out] {
        self.2
    }
}

/// A trait that provides a minimized view of an Orchard input suitable for use in fee and change
/// calculation.
pub trait InputView<NoteRef> {
    /// An identifier for the input being spent.
    fn note_id(&self) -> &NoteRef;
    /// The value of the input being spent.
    fn value(&self) -> NonNegativeAmount;
}

impl<N> InputView<N> for Infallible {
    fn note_id(&self) -> &N {
        unreachable!()
    }
    fn value(&self) -> NonNegativeAmount {
        unreachable!()
    }
}

/// A trait that provides a minimized view of a Orchard output suitable for use in fee and change
/// calculation.
pub trait OutputView {
    /// The value of the output being produced.
    fn value(&self) -> NonNegativeAmount;
}

impl OutputView for Infallible {
    fn value(&self) -> NonNegativeAmount {
        unreachable!()
    }
}
