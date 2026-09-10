//! Structs for building transactions.

use core::cmp::Ordering;
use core::fmt;

use rand_core::{CryptoRng, RngCore};

use ::sapling::{Note, PaymentAddress, builder::SaplingMetadata};
use ::transparent::{
    address::TransparentAddress, builder::TransparentBuilder, bundle::TxOut, coinbase,
};
use orchard::{builder::BuildError::BundleTypeNotSatisfiable, note::AssetBase};
use zcash_protocol::{
    PoolType,
    consensus::{self, BlockHeight, BranchId, Parameters},
    memo::MemoBytes,
    value::{BalanceError, ZatBalance, Zatoshis},
};
use zcash_script::opcode::PushValue;

use crate::transaction::{
    Transaction, TxVersion,
    components::orchard::bundle_version_for_branch,
    fees::{
        FeeRule,
        transparent::{InputView, OutputView},
    },
};

#[cfg(feature = "std")]
use std::sync::mpsc::Sender;

#[cfg(feature = "circuits")]
use {
    crate::transaction::{
        Authorization, Coinbase, TransactionData, TxDigests, Unauthorized,
        sighash::{SignableInput, signature_hash},
        txid::TxIdDigester,
    },
    ::sapling::prover::{OutputProver, SpendProver},
    ::transparent::builder::TransparentSigningSet,
    alloc::vec::Vec,
};

#[cfg(feature = "transparent-inputs")]
use {::transparent::builder::TransparentInputInfo, zcash_script::script};

#[cfg(not(feature = "transparent-inputs"))]
use core::convert::Infallible;

#[cfg(zcash_unstable = "nu7")]
use {
    orchard::{
        Address, bundle, issuance,
        issuance::auth::{IssueAuthKey, IssueValidatingKey, ZSASchnorr},
        issuance::{IssueBundle, IssueInfo},
        note::{AssetId, Nullifier},
    },
    rand_core::OsRng,
};

use super::components::sapling::zip212_enforcement;

/// Since Blossom activation, the default transaction expiry delta should be 40 blocks.
/// <https://zips.z.cash/zip-0203#changes-for-blossom>
pub const DEFAULT_TX_EXPIRY_DELTA: u32 = 40;

/// Errors that can occur during fee calculation.
#[derive(Debug)]
pub enum FeeError<FE> {
    FeeRule(FE),
    Bundle(&'static str),
}

impl<FE: fmt::Display> fmt::Display for FeeError<FE> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FeeError::FeeRule(e) => write!(f, "An error occurred in fee calculation: {e}"),
            FeeError::Bundle(b) => write!(f, "Bundle structure invalid in fee calculation: {b}"),
        }
    }
}

/// Errors that can occur during transaction construction.
#[derive(Debug)]
pub enum Error<FE> {
    /// Insufficient funds were provided to the transaction builder; the given
    /// additional amount is required in order to construct the transaction.
    InsufficientFunds(ZatBalance),
    /// The transaction has inputs in excess of outputs and fees; the user must
    /// add a change output.
    ChangeRequired(ZatBalance),
    /// An error occurred in computing the fees for a transaction.
    Fee(FeeError<FE>),
    /// An overflow or underflow occurred when computing value balances
    Balance(BalanceError),
    /// An error occurred in constructing the transparent parts of a transaction.
    TransparentBuild(transparent::builder::Error),
    /// An error occurred in constructing the Sapling parts of a transaction.
    SaplingBuild(sapling::builder::Error),
    /// An error occurred in constructing the Orchard parts of a transaction.
    OrchardBuild(orchard::builder::BuildError),
    /// An error occurred in constructing the Ironwood parts of a transaction.
    IronwoodBuild(orchard::builder::BuildError),
    /// An error occurred in adding an Orchard Spend to a transaction.
    OrchardSpend(orchard::builder::SpendError),
    /// An error occurred in adding an Orchard Output to a transaction.
    OrchardRecipient(orchard::builder::OutputError),
    /// An error occurred in adding an Ironwood Spend to a transaction.
    IronwoodSpend(orchard::builder::SpendError),
    /// An Ironwood spend note used an unsupported note plaintext version.
    IronwoodSpendUnsupportedNoteVersion(orchard::NoteVersion),
    /// An error occurred in adding an Ironwood Output to a transaction.
    IronwoodRecipient(orchard::builder::OutputError),
    /// The builder was constructed without support for the Sapling pool, but a Sapling
    /// spend or output was added.
    SaplingBuilderNotAvailable,
    /// The builder was constructed with a target height before NU5 activation, but an Orchard
    /// spend or output was added.
    OrchardBuilderNotAvailable,
    /// The builder was constructed with a target height before NU6.3 activation,
    /// or without an Ironwood anchor, but an Ironwood spend or output was added.
    IronwoodBuilderNotAvailable,
    /// The issuance bundle not initialized.
    #[cfg(zcash_unstable = "nu7")]
    IssuanceBuilderNotAvailable,
    /// The issuance key not initialized.
    #[cfg(zcash_unstable = "nu7")]
    IssuanceKeyNotAvailable,
    /// An error occurred in constructing the Issuance bundle.
    #[cfg(zcash_unstable = "nu7")]
    IssuanceBundle(issuance::Error),
    /// Issuance bundle already initialized.
    #[cfg(zcash_unstable = "nu7")]
    IssuanceBundleAlreadyInitialized,
    /// An error occurred in constructing a coinbase transaction.
    Coinbase(coinbase::Error),
    /// A coinbase transaction's expiry height does not match its target block height.
    CoinbaseExpiryHeightMismatch {
        target_height: BlockHeight,
        expiry_height: BlockHeight,
    },
    /// The proposed transaction version or the consensus branch id for the target height does not
    /// support a feature required by the transaction under construction, or the proposed
    /// transaction version is not supported on the given consensus branch.
    TargetIncompatible(BranchId, TxVersion, Option<PoolType>),
}

impl<FE: fmt::Display> fmt::Display for Error<FE> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InsufficientFunds(amount) => write!(
                f,
                "Insufficient funds for transaction construction; need an additional {amount:?} zatoshis"
            ),
            Error::ChangeRequired(amount) => write!(
                f,
                "The transaction requires an additional change output of {amount:?} zatoshis"
            ),
            Error::Balance(e) => write!(f, "Invalid amount {e:?}"),
            Error::Fee(e) => write!(f, "An error occurred in fee calculation: {e}"),
            Error::TransparentBuild(err) => err.fmt(f),
            Error::SaplingBuild(err) => err.fmt(f),
            Error::OrchardBuild(err) => write!(f, "{err:?}"),
            Error::IronwoodBuild(err) => write!(f, "{err:?}"),
            Error::OrchardSpend(err) => write!(f, "Could not add Orchard spend: {err}"),
            Error::OrchardRecipient(err) => write!(f, "Could not add Orchard recipient: {err}"),
            Error::IronwoodSpend(err) => write!(f, "Could not add Ironwood spend: {err}"),
            Error::IronwoodSpendUnsupportedNoteVersion(version) => write!(
                f,
                "Could not add Ironwood spend: note version {version:?} is unsupported"
            ),
            Error::IronwoodRecipient(err) => {
                write!(f, "Could not add Ironwood recipient: {err}")
            }
            Error::SaplingBuilderNotAvailable => write!(
                f,
                "Cannot create Sapling transactions without a Sapling anchor"
            ),
            Error::OrchardBuilderNotAvailable => write!(
                f,
                "Cannot create Orchard transactions without an Orchard anchor, or before NU5 activation"
            ),
            Error::IronwoodBuilderNotAvailable => write!(
                f,
                "Cannot create Ironwood transactions without an Ironwood anchor, or before NU6.3 activation"
            ),
            #[cfg(zcash_unstable = "nu7")]
            Error::IssuanceBuilderNotAvailable => write!(f, "Issuance bundle not initialized"),
            #[cfg(zcash_unstable = "nu7")]
            Error::IssuanceKeyNotAvailable => write!(f, "Issuance key not initialized"),
            #[cfg(zcash_unstable = "nu7")]
            Error::IssuanceBundle(err) => write!(f, "Issuance bundle internal error: {:?}", err),
            #[cfg(zcash_unstable = "nu7")]
            Error::IssuanceBundleAlreadyInitialized => {
                write!(f, "Issuance bundle already initialized")
            }
            Error::Coinbase(err) => write!(
                f,
                "An error occurred in constructing a coinbase transaction: {err}"
            ),
            Error::CoinbaseExpiryHeightMismatch {
                target_height,
                expiry_height,
            } => write!(
                f,
                "Coinbase transaction expiry height {expiry_height} does not match target block height {target_height}"
            ),
            Error::TargetIncompatible(branch_id, version, pool_type) => match pool_type {
                None => write!(
                    f,
                    "Proposed transaction version {version:?} is not valid for consensus branch {branch_id:?}"
                ),
                Some(t) => write!(
                    f,
                    "{t} is not supported for proposed transaction version {version:?} or consensus branch {branch_id:?}"
                ),
            },
        }
    }
}

#[cfg(feature = "std")]
impl<FE: fmt::Debug + fmt::Display> std::error::Error for Error<FE> {}

impl<FE> From<BalanceError> for Error<FE> {
    fn from(e: BalanceError) -> Self {
        Error::Balance(e)
    }
}

impl<FE> From<FeeError<FE>> for Error<FE> {
    fn from(e: FeeError<FE>) -> Self {
        Error::Fee(e)
    }
}

impl<FE> From<sapling::builder::Error> for Error<FE> {
    fn from(e: sapling::builder::Error) -> Self {
        Error::SaplingBuild(e)
    }
}

impl<FE> From<orchard::builder::SpendError> for Error<FE> {
    fn from(e: orchard::builder::SpendError) -> Self {
        Error::OrchardSpend(e)
    }
}

impl<FE> From<coinbase::Error> for Error<FE> {
    fn from(e: coinbase::Error) -> Self {
        Error::Coinbase(e)
    }
}

/// Reports on the progress made by the builder towards building a transaction.
pub struct Progress {
    /// The number of steps completed.
    cur: u32,
    /// The expected total number of steps (as of this progress update), if known.
    end: Option<u32>,
}

impl From<(u32, u32)> for Progress {
    fn from((cur, end): (u32, u32)) -> Self {
        Self {
            cur,
            end: Some(end),
        }
    }
}

impl Progress {
    /// Returns the number of steps completed so far while building the transaction.
    ///
    /// Note that each step may not be of the same complexity/duration.
    pub fn cur(&self) -> u32 {
        self.cur
    }

    /// Returns the total expected number of steps before this transaction will be ready,
    /// or `None` if the end is unknown as of this progress update.
    ///
    /// Note that each step may not be of the same complexity/duration.
    pub fn end(&self) -> Option<u32> {
        self.end
    }
}

/// Rules for how the builder should be configured for each shielded pool or coinbase tx.
#[derive(Clone)]
pub enum BuildConfig {
    Standard {
        sapling_anchor: Option<sapling::Anchor>,
        orchard_anchor: Option<orchard::Anchor>,
        ironwood_anchor: Option<orchard::Anchor>,
        orchard_pool_bundle_type: orchard::builder::BundleType,
    },
    Coinbase {
        miner_data: Option<PushValue>,
    },
}

impl BuildConfig {
    /// Returns the Sapling bundle type and anchor for this configuration.
    pub fn sapling_builder_config(
        &self,
    ) -> Option<(sapling::builder::BundleType, sapling::Anchor)> {
        match self {
            BuildConfig::Standard { sapling_anchor, .. } => sapling_anchor
                .as_ref()
                .map(|a| (sapling::builder::BundleType::DEFAULT, *a)),
            BuildConfig::Coinbase { .. } => Some((
                sapling::builder::BundleType::Coinbase,
                sapling::Anchor::empty_tree(),
            )),
        }
    }

    /// Returns the Orchard builder for this configuration.
    fn orchard_builder(
        &self,
        bundle_version: orchard::bundle::BundleVersion,
    ) -> Option<orchard::builder::Builder> {
        match self {
            BuildConfig::Standard {
                orchard_anchor,
                orchard_pool_bundle_type,
                ..
            } => orchard_anchor.as_ref().map(|a| {
                orchard::builder::Builder::new(
                    *orchard_pool_bundle_type,
                    bundle_version,
                    bundle_version.default_flags(),
                    *a,
                )
                .expect("the default flags are always representable for a transactional bundle")
            }),
            BuildConfig::Coinbase { .. }
                if bundle_version == orchard::bundle::BundleVersion::orchard_v3() =>
            {
                None
            }
            BuildConfig::Coinbase { .. } => Some(
                orchard::builder::Builder::new(
                    orchard::builder::BundleType::Coinbase,
                    bundle_version,
                    // Coinbase transactions have `enableSpends = 0`. Every protocol version
                    // for which a coinbase Orchard-pool bundle can be built (pre-NU6.3) permits
                    // cross-address transfers, so the spends-disabled flag set is representable.
                    orchard::bundle::Flags::SPENDS_DISABLED,
                    orchard::Anchor::empty_tree(),
                )
                .expect("spends-disabled flags are valid for a non-Orchard coinbase bundle"),
            ),
        }
    }

    /// Returns the Ironwood builder for this configuration.
    fn ironwood_builder(
        &self,
        bundle_version: orchard::bundle::BundleVersion,
    ) -> Option<orchard::builder::Builder> {
        match self {
            BuildConfig::Standard {
                ironwood_anchor,
                orchard_pool_bundle_type,
                ..
            } => ironwood_anchor.as_ref().map(|a| {
                orchard::builder::Builder::new(
                    *orchard_pool_bundle_type,
                    bundle_version,
                    bundle_version.default_flags(),
                    *a,
                )
                .expect("the default flags are always representable for an Ironwood bundle")
            }),
            BuildConfig::Coinbase { .. } => Some(
                orchard::builder::Builder::new(
                    orchard::builder::BundleType::Coinbase,
                    bundle_version,
                    orchard::bundle::Flags::SPENDS_DISABLED,
                    orchard::Anchor::empty_tree(),
                )
                .expect("spends-disabled flags are valid for an Ironwood coinbase bundle"),
            ),
        }
    }

    /// Returns `true` if this configuration is for building a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        matches!(self, BuildConfig::Coinbase { .. })
    }
}

/// The [`BundleVersion`] of the Ironwood slot for a transaction version: the ZSA bundle in v7,
/// the plain Ironwood bundle otherwise.
fn ironwood_bundle_version(version: TxVersion) -> orchard::bundle::BundleVersion {
    #[cfg(zcash_unstable = "nu7")]
    if version.has_orchard_zsa() {
        return orchard::bundle::BundleVersion::zsa();
    }
    let _ = version;
    orchard::bundle::BundleVersion::ironwood_v3()
}

fn orchard_action_count(
    builder: &orchard::builder::Builder,
    is_coinbase: bool,
    bundle_version: orchard::bundle::BundleVersion,
) -> Result<usize, &'static str> {
    let num_spends = builder.spends().len();
    let num_outputs = builder
        .outputs()
        .len()
        .checked_add(builder.changes().len())
        .ok_or("num_outputs + num_changes overflowed")?;

    // The bundle type must match the one the builder was constructed with (see
    // `orchard_builder` / `ironwood_builder`); read it back from the builder so
    // the two cannot drift.
    let bundle_type = builder.bundle_type();

    // The flags must match those the builder constructs for each configuration (see
    // `orchard_builder`). For a `Coinbase` bundle `num_actions` ignores the flags, but supplying
    // the matching set keeps the two paths consistent.
    let flags = if is_coinbase {
        orchard::bundle::Flags::SPENDS_DISABLED
    } else {
        bundle_version.default_flags()
    };

    bundle_type.num_actions(flags, num_spends, num_outputs)
}

/// The result of a transaction build operation, which includes the resulting transaction along
/// with metadata describing how spends and outputs were shuffled in creating the transaction's
/// shielded bundles.
#[derive(Debug)]
pub struct BuildResult {
    transaction: Transaction,
    sapling_meta: SaplingMetadata,
    orchard_meta: orchard::builder::BundleMetadata,
    ironwood_meta: orchard::builder::BundleMetadata,
}

impl BuildResult {
    /// Returns the transaction that was constructed by the builder.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Returns the mapping from Sapling inputs and outputs to their randomized positions in the
    /// Sapling bundle in the newly constructed transaction.
    pub fn sapling_meta(&self) -> &SaplingMetadata {
        &self.sapling_meta
    }

    /// Returns the mapping from Orchard inputs and outputs to the randomized positions of the
    /// Actions that contain them in the Orchard bundle in the newly constructed transaction.
    pub fn orchard_meta(&self) -> &orchard::builder::BundleMetadata {
        &self.orchard_meta
    }

    /// Returns the mapping from Ironwood inputs and outputs to the randomized
    /// positions of the Actions that contain them in the Ironwood bundle in
    /// the newly constructed transaction.
    pub fn ironwood_meta(&self) -> &orchard::builder::BundleMetadata {
        &self.ironwood_meta
    }
}

/// The result of [`Builder::build_for_pczt`].
///
/// It includes the PCZT components along with metadata describing how spends and outputs
/// were shuffled in creating the transaction's shielded bundles.
#[derive(Debug)]
pub struct PcztResult<P: Parameters> {
    pub pczt_parts: PcztParts<P>,
    pub sapling_meta: SaplingMetadata,
    pub orchard_meta: orchard::builder::BundleMetadata,
    pub ironwood_meta: orchard::builder::BundleMetadata,
}

/// The components of a PCZT.
#[derive(Debug)]
pub struct PcztParts<P: Parameters> {
    pub params: P,
    pub version: TxVersion,
    pub consensus_branch_id: BranchId,
    pub lock_time: u32,
    pub expiry_height: BlockHeight,
    pub transparent: Option<transparent::pczt::Bundle>,
    pub sapling: Option<sapling::pczt::Bundle>,
    pub orchard: Option<orchard::pczt::Bundle>,
    pub ironwood: Option<orchard::pczt::Bundle>,
}

/// Generates a [`Transaction`] from its inputs and outputs.
pub struct Builder<P, U> {
    params: P,
    tx_version: TxVersion,
    consensus_branch_id: BranchId,
    build_config: BuildConfig,
    target_height: BlockHeight,
    expiry_height: BlockHeight,
    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
    zip233_amount: Zatoshis,
    transparent_builder: TransparentBuilder,
    sapling_builder: Option<sapling::builder::Builder>,
    orchard_builder: Option<orchard::builder::Builder>,
    orchard_bundle_version: Option<orchard::bundle::BundleVersion>,
    ironwood_builder: Option<orchard::builder::Builder>,
    #[cfg(zcash_unstable = "nu7")]
    issuance_builder: Option<IssueBundle<issuance::AwaitingNullifier>>,
    #[cfg(zcash_unstable = "nu7")]
    issuance_isk: Option<orchard::issuance::auth::IssueAuthKey<ZSASchnorr>>,
    _progress_notifier: U,
}

impl<P, U> Builder<P, U> {
    /// Returns the network parameters that the builder has been configured for.
    pub fn params(&self) -> &P {
        &self.params
    }

    /// Returns the target height of the transaction under construction.
    pub fn target_height(&self) -> BlockHeight {
        self.target_height
    }

    /// Returns the set of transparent inputs currently committed to be consumed
    /// by the transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent_inputs(&self) -> &[TransparentInputInfo] {
        self.transparent_builder.inputs()
    }

    /// Returns the set of transparent outputs currently set to be produced by
    /// the transaction.
    pub fn transparent_outputs(&self) -> &[TxOut] {
        self.transparent_builder.outputs()
    }

    /// Returns the set of Sapling inputs currently committed to be consumed
    /// by the transaction.
    pub fn sapling_inputs(&self) -> &[sapling::builder::SpendInfo] {
        self.sapling_builder
            .as_ref()
            .map_or_else(|| &[][..], |b| b.inputs())
    }

    /// Returns the set of Sapling outputs currently set to be produced by
    /// the transaction.
    pub fn sapling_outputs(&self) -> &[sapling::builder::OutputInfo] {
        self.sapling_builder
            .as_ref()
            .map_or_else(|| &[][..], |b| b.outputs())
    }

    /// Returns `true` if any Orchard spend, output, or change output has been
    /// added to this builder (i.e. the transaction will carry an Orchard bundle).
    fn orchard_in_use(&self) -> bool {
        self.orchard_builder.as_ref().is_some_and(|b| {
            !b.spends().is_empty() || !b.outputs().is_empty() || !b.changes().is_empty()
        })
    }

    /// Returns `true` if any Ironwood spend, output, or change output has been
    /// added to this builder (i.e. the transaction will carry an Ironwood bundle).
    fn ironwood_in_use(&self) -> bool {
        self.ironwood_builder.as_ref().is_some_and(|b| {
            !b.spends().is_empty() || !b.outputs().is_empty() || !b.changes().is_empty()
        })
    }

    /// Checks that the given version supports all features required by the inputs and
    /// outputs already added to the builder.
    fn check_version_compatibility<FE>(&self, version: TxVersion) -> Result<(), Error<FE>> {
        if !version.valid_in_branch(self.consensus_branch_id) {
            return Err(Error::TargetIncompatible(
                self.consensus_branch_id,
                version,
                None,
            ));
        }

        let sapling_available = version.has_sapling() && self.consensus_branch_id.has_sapling();
        if !sapling_available
            && (!self.sapling_inputs().is_empty() || !self.sapling_outputs().is_empty())
        {
            return Err(Error::TargetIncompatible(
                self.consensus_branch_id,
                version,
                Some(PoolType::SAPLING),
            ));
        }

        let orchard_available = version.has_orchard() && self.consensus_branch_id.has_orchard();
        if !orchard_available && self.orchard_in_use() {
            return Err(Error::TargetIncompatible(
                self.consensus_branch_id,
                version,
                Some(PoolType::ORCHARD),
            ));
        }

        {
            // Ironwood is available only when the target version carries an Ironwood bundle
            // (V6) and the consensus branch is one in which Ironwood is active.
            let ironwood_branch = match self.consensus_branch_id {
                BranchId::Nu6_3 => true,
                #[cfg(zcash_unstable = "nu7")]
                BranchId::Nu7 => true,
                _ => false,
            };
            let ironwood_available = version.has_ironwood() && ironwood_branch;
            if !ironwood_available && self.ironwood_in_use() {
                return Err(Error::TargetIncompatible(
                    self.consensus_branch_id,
                    version,
                    None,
                ));
            }
        }

        Ok(())
    }

    /// Proposes a specific transaction version.
    ///
    /// Validates that the proposed version supports all features required by
    /// the inputs and outputs already added to the builder. Returns
    /// [`Error::TargetIncompatible`] if validation fails.
    ///
    /// The same validation is performed at build time to catch inputs/outputs
    /// added after this call.
    pub fn propose_version<FE>(&mut self, version: TxVersion) -> Result<(), Error<FE>> {
        self.check_version_compatibility(version)?;
        self.tx_version = version;
        Ok(())
    }
}

impl<P: consensus::Parameters> Builder<P, ()> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height,
    /// using default values for general transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    pub fn new(params: P, target_height: BlockHeight, build_config: BuildConfig) -> Self {
        let consensus_branch_id = BranchId::for_height(&params, target_height);
        // `bundle_version_for_branch` returns `Some` exactly for the branches in
        // which the Orchard pool is supported (NU5 onward), so this also gates
        // Orchard builder construction on NU5 activation.
        let bundle_version =
            bundle_version_for_branch(consensus_branch_id, orchard::ValuePool::Orchard);
        // Default transaction version for the branch (V6 from NU6.3 onward).
        let tx_version = TxVersion::suggested_for_branch(consensus_branch_id);

        let orchard_builder = bundle_version.and_then(|v| build_config.orchard_builder(v));
        let orchard_bundle_version = orchard_builder.as_ref().and(bundle_version);

        // The Ironwood builder exists exactly when the branch's transaction version
        // carries an Ironwood bundle (V6, i.e. NU6.3 onward).
        let ironwood_builder = if tx_version.has_ironwood() {
            build_config.ironwood_builder(ironwood_bundle_version(tx_version))
        } else {
            None
        };

        let sapling_builder = build_config
            .sapling_builder_config()
            .map(|(bundle_type, anchor)| {
                sapling::builder::Builder::new(
                    zip212_enforcement(&params, target_height),
                    bundle_type,
                    anchor,
                )
            });

        // # Consensus Rules
        //
        // > [NU5 onward] The `nExpiryHeight` field of a coinbase transaction MUST be equal to its
        // > block height.
        //
        // ## Notes
        //
        // We set the expiry height for coinbase txs to the block height regardless of the network
        // upgrade.
        let expiry_height = if build_config.is_coinbase() {
            target_height
        } else {
            target_height + DEFAULT_TX_EXPIRY_DELTA
        };

        Builder {
            params,
            tx_version,
            consensus_branch_id,
            build_config,
            target_height,
            expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: Zatoshis::ZERO,
            transparent_builder: TransparentBuilder::empty(),
            sapling_builder,
            orchard_builder,
            orchard_bundle_version,
            ironwood_builder,
            #[cfg(zcash_unstable = "nu7")]
            issuance_builder: None,
            #[cfg(zcash_unstable = "nu7")]
            issuance_isk: None,
            _progress_notifier: (),
        }
    }

    /// Sets the notifier channel, where progress of building the transaction is sent.
    ///
    /// An update is sent after every Sapling Spend or Output is computed, and the `u32`
    /// sent represents the total steps completed so far. It will eventually send number
    /// of spends + outputs. If there's an error building the transaction, the channel is
    /// closed.
    #[cfg(feature = "std")]
    pub fn with_progress_notifier(
        self,
        _progress_notifier: Sender<Progress>,
    ) -> Builder<P, Sender<Progress>> {
        Builder {
            params: self.params,
            tx_version: self.tx_version,
            consensus_branch_id: self.consensus_branch_id,
            build_config: self.build_config,
            target_height: self.target_height,
            expiry_height: self.expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: self.zip233_amount,
            transparent_builder: self.transparent_builder,
            sapling_builder: self.sapling_builder,
            orchard_builder: self.orchard_builder,
            orchard_bundle_version: self.orchard_bundle_version,
            ironwood_builder: self.ironwood_builder,
            #[cfg(zcash_unstable = "nu7")]
            issuance_builder: self.issuance_builder,
            #[cfg(zcash_unstable = "nu7")]
            issuance_isk: self.issuance_isk,
            _progress_notifier,
        }
    }

    /// Creates IssuanceBundle and adds an Issuance action to the transaction.
    #[cfg(zcash_unstable = "nu7")]
    pub fn init_issuance_bundle<FE>(
        &mut self,
        ik: IssueAuthKey<ZSASchnorr>,
        asset_desc_hash: [u8; 32],
        issue_info: Option<IssueInfo>,
        first_issuance: bool,
    ) -> Result<(), Error<FE>> {
        if !self.tx_version.has_orchard_zsa() {
            return Err(Error::OrchardBuild(BundleTypeNotSatisfiable));
        }

        if self.issuance_builder.is_some() {
            return Err(Error::IssuanceBundleAlreadyInitialized);
        }

        let (bundle, _) = IssueBundle::new(
            IssueValidatingKey::<ZSASchnorr>::from(&ik),
            asset_desc_hash,
            issue_info,
            first_issuance,
            OsRng,
        );

        self.issuance_builder = Some(bundle);
        self.issuance_isk = Some(ik);

        Ok(())
    }

    /// Adds an Issuance action to the transaction.
    #[cfg(zcash_unstable = "nu7")]
    pub fn add_recipient<FE>(
        &mut self,
        asset_desc_hash: [u8; 32],
        recipient: Address,
        value: orchard::value::NoteValue,
        first_issuance: bool,
    ) -> Result<(), Error<FE>> {
        if !self.tx_version.has_orchard_zsa() {
            return Err(Error::OrchardBuild(BundleTypeNotSatisfiable));
        }

        self.issuance_builder
            .as_mut()
            .ok_or(Error::IssuanceBuilderNotAvailable)?
            .add_recipient(asset_desc_hash, recipient, value, first_issuance, OsRng)
            .map_err(Error::IssuanceBundle)?;

        Ok(())
    }

    /// Finalizes a given asset
    #[cfg(zcash_unstable = "nu7")]
    pub fn finalize_asset<FE>(&mut self, asset_desc_hash: &[u8; 32]) -> Result<(), Error<FE>> {
        if !self.tx_version.has_orchard_zsa() {
            return Err(Error::OrchardBuild(BundleTypeNotSatisfiable));
        }

        self.issuance_builder
            .as_mut()
            .ok_or(Error::IssuanceBuilderNotAvailable)?
            .finalize_action(asset_desc_hash)
            .map_err(Error::IssuanceBundle)?;

        Ok(())
    }

    /// Adds a Burn action to the transaction.
    #[cfg(zcash_unstable = "nu7")]
    pub fn add_burn<FE>(&mut self, value: u64, asset: AssetBase) -> Result<(), Error<FE>> {
        if !self.tx_version.has_orchard_zsa() {
            return Err(Error::OrchardBuild(BundleTypeNotSatisfiable));
        }

        self.orchard_builder
            .as_mut()
            .ok_or(Error::OrchardBuilderNotAvailable)?
            .add_burn(asset, orchard::value::NoteValue::from_raw(value))
            .map_err(Error::OrchardBuild)?;

        Ok(())
    }
}

impl<P: consensus::Parameters, U> Builder<P, U> {
    /// Overrides the expiry height for the transaction under construction.
    ///
    /// For non-coinbase transactions, setting this to `BlockHeight::from(0)`
    /// disables transaction expiry. Coinbase builders reject overridden expiry
    /// heights that do not match the target block height.
    ///
    /// Disabling expiry by setting the height to `BlockHeight::from(0)` is not
    /// recommended: non-expiring transactions are not yet well tested
    /// end-to-end and are known to cause bugs elsewhere in the stack. Callers
    /// should avoid a zero expiry height unless they specifically need it.
    pub fn with_expiry_height(mut self, expiry_height: BlockHeight) -> Self {
        self.expiry_height = expiry_height;
        self
    }

    /// Verifies that a coinbase transaction's expiry height matches its target
    /// block height, as required for coinbase transactions.
    fn check_coinbase_expiry_height<FE>(&self) -> Result<(), Error<FE>> {
        if self.build_config.is_coinbase() && self.expiry_height != self.target_height {
            Err(Error::CoinbaseExpiryHeightMismatch {
                target_height: self.target_height,
                expiry_height: self.expiry_height,
            })
        } else {
            Ok(())
        }
    }

    /// Adds an Orchard note to be spent in this bundle.
    ///
    /// Returns an error if the given Merkle path does not have the required anchor for
    /// the given note.
    pub fn add_orchard_spend<FE>(
        &mut self,
        fvk: orchard::keys::FullViewingKey,
        note: orchard::Note,
        merkle_path: orchard::tree::MerklePath,
    ) -> Result<(), Error<FE>> {
        if let Some(builder) = self.orchard_builder.as_mut() {
            builder.add_spend(fvk, note, merkle_path)?;
            Ok(())
        } else {
            Err(Error::OrchardBuilderNotAvailable)
        }
    }

    /// Adds an Orchard recipient to the transaction.
    pub fn add_orchard_output<FE>(
        &mut self,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: orchard::Address,
        value: Zatoshis,
        asset: AssetBase,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        if !bool::from(asset.is_zatoshi()) && !self.tx_version.has_orchard_zsa() {
            return Err(Error::OrchardBuild(BundleTypeNotSatisfiable));
        }

        self.orchard_builder
            .as_mut()
            .ok_or(Error::OrchardBuilderNotAvailable)?
            .add_output(
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value.into()),
                asset,
                memo.into_bytes(),
            )
            .map_err(Error::OrchardRecipient)
    }

    /// Adds a wallet-controlled Orchard change output to the transaction.
    ///
    /// Returns [`Error::OrchardBuilderNotAvailable`] if this builder is not
    /// configured with an Orchard bundle builder. Returns
    /// [`Error::OrchardRecipient`] if the Orchard builder rejects the recipient
    /// or cannot construct the output.
    pub fn add_orchard_change_output<FE>(
        &mut self,
        fvk: orchard::keys::FullViewingKey,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: orchard::Address,
        value: Zatoshis,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.orchard_builder
            .as_mut()
            .ok_or(Error::OrchardBuilderNotAvailable)?
            .add_change_output(
                fvk,
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value.into()),
                // Change in the Orchard value pool is always ZEC.
                AssetBase::zatoshi(),
                memo.into_bytes(),
            )
            .map_err(Error::OrchardRecipient)
    }

    /// Adds an Ironwood note to be spent in this bundle.
    ///
    /// The note must use the plaintext version of the transaction's Ironwood slot:
    /// [`orchard::note::NoteVersion::ZSA`] in a v7 transaction, and
    /// [`orchard::note::NoteVersion::V3`] otherwise.
    ///
    /// Returns an error if the given note has an unsupported version, or if
    /// the given Merkle path does not have the required Ironwood anchor for the
    /// note.
    pub fn add_ironwood_spend<FE>(
        &mut self,
        fvk: orchard::keys::FullViewingKey,
        note: orchard::Note,
        merkle_path: orchard::tree::MerklePath,
    ) -> Result<(), Error<FE>> {
        // In a v7 transaction the Ironwood slot carries ZSA notes instead of Ironwood v3 ones.
        let expected_version = if self.tx_version.has_orchard_zsa() {
            orchard::note::NoteVersion::ZSA
        } else {
            orchard::note::NoteVersion::V3
        };

        let builder = self
            .ironwood_builder
            .as_mut()
            .ok_or(Error::IronwoodBuilderNotAvailable)?;

        if note.version() != expected_version {
            return Err(Error::IronwoodSpendUnsupportedNoteVersion(note.version()));
        }

        builder
            .add_spend(fvk, note, merkle_path)
            .map_err(Error::IronwoodSpend)?;
        Ok(())
    }

    /// Adds an Ironwood recipient to the transaction.
    ///
    /// The note uses the plaintext version of the transaction's Ironwood slot:
    /// [`orchard::note::NoteVersion::ZSA`] in a v7 transaction, and
    /// [`orchard::note::NoteVersion::V3`] otherwise.
    pub fn add_ironwood_output<FE>(
        &mut self,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: orchard::Address,
        value: Zatoshis,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.ironwood_builder
            .as_mut()
            .ok_or(Error::IronwoodBuilderNotAvailable)?
            .add_output(
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value.into()),
                // FIXME: v7 puts ZSA in the Ironwood slot, so the asset belongs on this method
                // rather than on `add_orchard_output`; until that is rewired, only ZEC is possible.
                AssetBase::zatoshi(),
                memo.into_bytes(),
            )
            .map_err(Error::IronwoodRecipient)
    }

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_sapling_spend<FE>(
        &mut self,
        fvk: sapling::keys::FullViewingKey,
        note: Note,
        merkle_path: sapling::MerklePath,
    ) -> Result<(), Error<FE>> {
        if let Some(builder) = self.sapling_builder.as_mut() {
            builder.add_spend(fvk, note, merkle_path)?;
            Ok(())
        } else {
            Err(Error::SaplingBuilderNotAvailable)
        }
    }

    /// Adds a Sapling address to send funds to.
    pub fn add_sapling_output<FE>(
        &mut self,
        ovk: Option<sapling::keys::OutgoingViewingKey>,
        to: PaymentAddress,
        value: Zatoshis,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.sapling_builder
            .as_mut()
            .ok_or(Error::SaplingBuilderNotAvailable)?
            .add_output(
                ovk,
                to,
                sapling::value::NoteValue::from_raw(u64::from(value)),
                memo.into_bytes(),
            )
            .map_err(Error::SaplingBuild)
    }

    /// Adds a transparent coin to be spent in this transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_transparent_input(&mut self, input: TransparentInputInfo) {
        self.transparent_builder.add_input(input)
    }

    /// Adds a transparent P2PKH coin to be spent in this transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_transparent_p2pkh_input(
        &mut self,
        pubkey: secp256k1::PublicKey,
        utxo: transparent::bundle::OutPoint,
        coin: TxOut,
    ) -> Result<(), transparent::builder::Error> {
        self.transparent_builder.add_p2pkh_input(pubkey, utxo, coin)
    }

    /// Adds a transparent P2SH coin to be spent in this transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_transparent_p2sh_input(
        &mut self,
        redeem_script: script::FromChain,
        utxo: transparent::bundle::OutPoint,
        coin: TxOut,
    ) -> Result<(), transparent::builder::Error> {
        self.transparent_builder
            .add_p2sh_input(redeem_script, utxo, coin)
    }

    /// Adds a transparent address to send funds to.
    pub fn add_transparent_output(
        &mut self,
        to: &TransparentAddress,
        value: Zatoshis,
    ) -> Result<(), transparent::builder::Error> {
        self.transparent_builder.add_output(to, value)
    }

    /// Adds a transparent "null data" (OP_RETURN) output with the given data payload.
    pub fn add_transparent_null_data_output<FE>(&mut self, data: &[u8]) -> Result<(), Error<FE>> {
        self.transparent_builder
            .add_null_data_output(data)
            .map_err(Error::TransparentBuild)
    }

    /// Returns the sum of the transparent, Sapling, Orchard, and zip233_amount value balances.
    fn value_balance(&self) -> Result<ZatBalance, BalanceError> {
        let value_balances = [
            self.transparent_builder.value_balance()?,
            self.sapling_builder
                .as_ref()
                .map_or_else(ZatBalance::zero, |builder| {
                    builder.value_balance::<ZatBalance>()
                }),
            self.orchard_builder.as_ref().map_or_else(
                || Ok(ZatBalance::zero()),
                |builder| {
                    builder
                        .value_balance::<ZatBalance>()
                        .map_err(|_| BalanceError::Overflow)
                },
            )?,
            self.ironwood_builder.as_ref().map_or_else(
                || Ok(ZatBalance::zero()),
                |builder| {
                    builder
                        .value_balance::<ZatBalance>()
                        .map_err(|_| BalanceError::Overflow)
                },
            )?,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            -ZatBalance::from(self.zip233_amount),
        ];

        value_balances
            .into_iter()
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)
    }

    /// Reports the calculated fee given the specified fee rule.
    ///
    /// This fee is a function of the spends and outputs that have been added to the builder,
    /// pursuant to the specified [`FeeRule`].
    pub fn get_fee<FR: FeeRule>(
        &self,
        fee_rule: &FR,
        #[cfg(zcash_unstable = "nu7")] is_new_asset: impl Fn(&AssetBase) -> bool,
    ) -> Result<Zatoshis, FeeError<FR::Error>> {
        #[cfg(feature = "transparent-inputs")]
        let transparent_inputs = self.transparent_builder.inputs();

        #[cfg(not(feature = "transparent-inputs"))]
        let transparent_inputs: &[Infallible] = &[];

        let sapling_spends = self
            .sapling_builder
            .as_ref()
            .map_or(0, |builder| builder.inputs().len());

        let ironwood_actions = self
            .ironwood_builder
            .as_ref()
            .map_or(Ok(0), |builder| {
                orchard_action_count(
                    builder,
                    self.build_config.is_coinbase(),
                    ironwood_bundle_version(self.tx_version),
                )
            })
            .map_err(FeeError::Bundle)?;

        fee_rule
            .fee_required(
                &self.params,
                self.target_height,
                transparent_inputs.iter().map(|i| i.serialized_size()),
                self.transparent_builder
                    .outputs()
                    .iter()
                    .map(|i| i.serialized_size()),
                sapling_spends,
                self.sapling_builder
                    .as_ref()
                    .zip(self.build_config.sapling_builder_config())
                    .map_or(Ok(0), |(builder, (bundle_type, _))| {
                        bundle_type
                            .num_outputs(sapling_spends, builder.outputs().len())
                            .map_err(FeeError::Bundle)
                    })?,
                self.orchard_builder
                    .as_ref()
                    .map_or(Ok(0), |builder| {
                        orchard_action_count(
                            builder,
                            self.build_config.is_coinbase(),
                            self.orchard_bundle_version
                                .expect("orchard builder present implies bundle version"),
                        )
                    })
                    .map_err(FeeError::Bundle)?,
                ironwood_actions,
                #[cfg(zcash_unstable = "nu7")]
                self.issuance_builder.as_ref().map_or(0, |bundle| {
                    bundle
                        .actions()
                        .iter()
                        .filter(|&action| {
                            is_new_asset(&AssetBase::custom(&AssetId::new_v0(
                                bundle.ik(),
                                action.asset_desc_hash(),
                            )))
                        })
                        .count()
                }),
                #[cfg(zcash_unstable = "nu7")]
                self.issuance_builder
                    .as_ref()
                    .map_or(0, |bundle| bundle.get_all_notes().len()),
            )
            .map_err(FeeError::FeeRule)
    }

    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
    pub fn set_zip233_amount(&mut self, zip233_amount: Zatoshis) {
        self.zip233_amount = zip233_amount;
    }
}

#[cfg(all(feature = "circuits", zcash_unstable = "nu7"))]
trait BuildInternalAuth:
    Authorization<
        SaplingAuth = sapling::builder::InProgress<
            sapling::builder::Proven,
            sapling::builder::Unsigned,
        >,
        OrchardAuth = orchard::builder::InProgress<
            orchard::builder::Unproven,
            orchard::builder::Unauthorized,
        >,
        IssueAuth = orchard::issuance::AwaitingSighash,
    >
{
}

#[cfg(all(feature = "circuits", zcash_unstable = "nu7"))]
impl<T> BuildInternalAuth for T where
    T: Authorization<
            SaplingAuth = sapling::builder::InProgress<
                sapling::builder::Proven,
                sapling::builder::Unsigned,
            >,
            OrchardAuth = orchard::builder::InProgress<
                orchard::builder::Unproven,
                orchard::builder::Unauthorized,
            >,
            IssueAuth = orchard::issuance::AwaitingSighash,
        >
{
}

#[cfg(all(feature = "circuits", not(zcash_unstable = "nu7")))]
trait BuildInternalAuth:
    Authorization<
        SaplingAuth = sapling::builder::InProgress<
            sapling::builder::Proven,
            sapling::builder::Unsigned,
        >,
        OrchardAuth = orchard::builder::InProgress<
            orchard::builder::Unproven,
            orchard::builder::Unauthorized,
        >,
    >
{
}

#[cfg(all(feature = "circuits", not(zcash_unstable = "nu7")))]
impl<T> BuildInternalAuth for T where
    T: Authorization<
            SaplingAuth = sapling::builder::InProgress<
                sapling::builder::Proven,
                sapling::builder::Unsigned,
            >,
            OrchardAuth = orchard::builder::InProgress<
                orchard::builder::Unproven,
                orchard::builder::Unauthorized,
            >,
        >
{
}

impl<P: consensus::Parameters, U: sapling::builder::ProverProgress> Builder<P, U> {
    /// Builds a transaction from the configured spends and outputs.
    ///
    /// Upon success, returns a [`BuildResult`] containing:
    ///
    /// - the [final transaction],
    /// - the [Sapling metadata], and
    /// - the [Orchard metadata]
    ///
    /// generated during the build process.
    ///
    /// [Sapling metadata]: ::sapling::builder::SaplingMetadata
    /// [Orchard metadata]: ::orchard::builder::BundleMetadata
    /// [final transaction]: Transaction
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "circuits")]
    pub fn build<R: RngCore + CryptoRng, SP: SpendProver, OP: OutputProver, FR: FeeRule>(
        self,
        transparent_signing_set: &TransparentSigningSet,
        sapling_extsks: &[sapling::zip32::ExtendedSpendingKey],
        orchard_saks: &[orchard::keys::SpendAuthorizingKey],
        rng: R,
        spend_prover: &SP,
        output_prover: &OP,
        fee_rule: &FR,
        #[cfg(zcash_unstable = "nu7")] is_new_asset: impl Fn(&AssetBase) -> bool,
    ) -> Result<BuildResult, Error<FR::Error>> {
        match &self.build_config {
            BuildConfig::Coinbase { miner_data } => {
                let target_height = self.target_height;
                let miner_data = miner_data.clone();

                self.build_internal::<Coinbase, _, _, _, _>(
                    |b| {
                        b.build_coinbase(target_height, miner_data)
                            .map(Some)
                            .map_err(Error::Coinbase)
                    },
                    |b, _, _| Ok(b.clone().map_authorization(transparent::builder::Coinbase)),
                    &[],
                    &[],
                    rng,
                    spend_prover,
                    output_prover,
                    None,
                )
            }
            BuildConfig::Standard { .. } => {
                let fee = self
                    .get_fee(
                        fee_rule,
                        #[cfg(zcash_unstable = "nu7")]
                        is_new_asset,
                    )
                    .map_err(Error::Fee)?;
                self.build_internal::<Unauthorized, _, _, _, _>(
                    |b| Ok(b.build()),
                    |b, unauthed_tx, txid_parts| {
                        authorize_transparent(b, unauthed_tx, txid_parts, transparent_signing_set)
                    },
                    sapling_extsks,
                    orchard_saks,
                    rng,
                    spend_prover,
                    output_prover,
                    Some(fee),
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "circuits")]
    fn build_internal<A, R, SP, OP, FE>(
        self,
        build_transparent: impl FnOnce(
            TransparentBuilder,
        ) -> Result<
            Option<transparent::bundle::Bundle<A::TransparentAuth>>,
            Error<FE>,
        >,
        authorize_transparent: impl FnOnce(
            &transparent::bundle::Bundle<A::TransparentAuth>,
            &TransactionData<A>,
            &TxDigests<blake2b_simd::Hash>,
        ) -> Result<
            transparent::bundle::Bundle<transparent::bundle::Authorized>,
            transparent::builder::Error,
        >,
        sapling_extsks: &[sapling::zip32::ExtendedSpendingKey],
        orchard_saks: &[orchard::keys::SpendAuthorizingKey],
        mut rng: R,
        spend_prover: &SP,
        output_prover: &OP,
        fee: Option<Zatoshis>,
    ) -> Result<BuildResult, Error<FE>>
    where
        A: BuildInternalAuth,
        A::TransparentAuth: transparent::sighash::TransparentAuthorizingContext,
        R: RngCore + CryptoRng,
        SP: SpendProver,
        OP: OutputProver,
    {
        self.check_version_compatibility::<FE>(self.tx_version)?;
        self.check_coinbase_expiry_height::<FE>()?;

        //
        // Consistency checks
        //

        assert_eq!(self.build_config.is_coinbase(), fee.is_none());
        if let Some(fee) = fee {
            // After fees are accounted for, the value balance of the transaction must be zero.
            let balance_after_fees =
                (self.value_balance()? - fee).ok_or(BalanceError::Underflow)?;

            match balance_after_fees.cmp(&ZatBalance::zero()) {
                Ordering::Less => {
                    return Err(Error::InsufficientFunds(-balance_after_fees));
                }
                Ordering::Greater => {
                    return Err(Error::ChangeRequired(balance_after_fees));
                }
                Ordering::Equal => (),
            };
        }

        let transparent_bundle = build_transparent(self.transparent_builder)?;

        let (sapling_bundle, sapling_meta) = match self
            .sapling_builder
            .and_then(|builder| {
                builder
                    .build::<SP, OP, _, _>(sapling_extsks, &mut rng)
                    .map_err(Error::SaplingBuild)
                    .transpose()
                    .map(|res| {
                        res.map(|(bundle, sapling_meta)| {
                            // We need to create proofs before signatures, because we still support
                            // creating V4 transactions, which commit to the Sapling proofs in the
                            // transaction digest.
                            (
                                bundle.create_proofs(
                                    spend_prover,
                                    output_prover,
                                    &mut rng,
                                    self._progress_notifier,
                                ),
                                sapling_meta,
                            )
                        })
                    })
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, SaplingMetadata::empty()),
        };

        let (unproven_orchard_bundle, orchard_meta) = match self
            .orchard_builder
            .and_then(|builder| {
                builder
                    .build(&mut rng)
                    .map_err(Error::OrchardBuild)
                    .transpose()
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, orchard::builder::BundleMetadata::empty()),
        };

        let (ironwood_bundle, ironwood_meta) = match self
            .ironwood_builder
            .and_then(|builder| {
                builder
                    .build(&mut rng)
                    .map_err(Error::IronwoodBuild)
                    .transpose()
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, orchard::builder::BundleMetadata::empty()),
        };

        #[cfg(zcash_unstable = "nu7")]
        let issue_bundle_awaiting_sighash = match self.issuance_builder {
            Some(b) => {
                let nullifier =
                    first_nullifier(&ironwood_bundle).ok_or(Error::<FE>::OrchardBuild(
                        orchard::builder::BuildError::BundleTypeNotSatisfiable,
                    ))?;
                Some(b.update_rho(nullifier, &mut rng))
            }
            None => None,
        };

        let unauthed_tx: TransactionData<A> = TransactionData {
            version: self.tx_version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: 0,
            expiry_height: self.expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: self.zip233_amount,
            transparent_bundle,
            // We don't support constructing Sprout bundles.
            //
            // # Consensus
            //
            // > A coinbase transaction MUST NOT have any JoinSplit descriptions.
            //
            // > A coinbase transaction MUST NOT have any Spend descriptions.
            //
            // <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle: unproven_orchard_bundle,
            ironwood_bundle,
            #[cfg(zcash_unstable = "nu7")]
            issue_bundle: issue_bundle_awaiting_sighash,
        };

        //
        // Signatures -- everything but the signatures must already have been added.
        //
        let txid_parts = unauthed_tx.digest(TxIdDigester);

        let transparent_bundle = unauthed_tx
            .transparent_bundle
            .as_ref()
            .map(|b| authorize_transparent(b, &unauthed_tx, &txid_parts))
            .transpose()
            .map_err(Error::TransparentBuild)?;

        // the commitment being signed is shared across all Sapling inputs; once
        // V4 transactions are deprecated this should just be the txid, but
        // for now we need to continue to compute it here.
        let shielded_sig_commitment =
            signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

        let sapling_asks = sapling_extsks
            .iter()
            .map(|extsk| extsk.expsk.ask.clone())
            .collect::<Vec<_>>();
        let sapling_bundle = unauthed_tx
            .sapling_bundle
            .map(|b| b.apply_signatures(&mut rng, *shielded_sig_commitment.as_ref(), &sapling_asks))
            .transpose()
            .map_err(Error::SaplingBuild)?;

        // A bundle is proved under the circuit its own `BundleVersion` selects. In a v6
        // transaction both slots share the post-NU6.3 circuit, but in a v7 transaction the
        // Ironwood slot is ZSA and uses the ZSA circuit, so each slot gets its own key.
        let proving_key_for = |bundle_version: orchard::bundle::BundleVersion| {
            orchard::circuit::ProvingKey::build(bundle_version.circuit_version())
        };

        let orchard_bundle = unauthed_tx
            .orchard_bundle
            .map(|b| {
                let pk = proving_key_for(b.bundle_version());
                b.create_proof(&pk, &mut rng).and_then(|b| {
                    b.apply_signatures(&mut rng, *shielded_sig_commitment.as_ref(), orchard_saks)
                })
            })
            .transpose()
            .map_err(Error::OrchardBuild)?;

        #[cfg(zcash_unstable = "nu7")]
        let issue_bundle = if let Some(bundle) = unauthed_tx.issue_bundle {
            let prepared = bundle.prepare(*shielded_sig_commitment.as_ref());
            let isk = self
                .issuance_isk
                .as_ref()
                .ok_or_else(|| Error::IssuanceKeyNotAvailable)?;
            Some(prepared.sign(isk).map_err(Error::IssuanceBundle)?)
        } else {
            None
        };

        let ironwood_bundle = unauthed_tx
            .ironwood_bundle
            .map(|b| {
                let pk = proving_key_for(b.bundle_version());
                b.create_proof(&pk, &mut rng).and_then(|b| {
                    // Ironwood actions use the Orchard bundle type and the same
                    // Orchard spend authority. The `IronwoodNu6_3Onward` pool
                    // restrictions select the Ironwood circuit and flag rules;
                    // `apply_signatures` only signs actions whose `ak` matches
                    // a supplied spend authorizing key.
                    b.apply_signatures(&mut rng, *shielded_sig_commitment.as_ref(), orchard_saks)
                })
            })
            .transpose()
            .map_err(Error::IronwoodBuild)?;

        let authorized_tx = TransactionData {
            version: unauthed_tx.version,
            consensus_branch_id: unauthed_tx.consensus_branch_id,
            lock_time: unauthed_tx.lock_time,
            expiry_height: unauthed_tx.expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: unauthed_tx.zip233_amount,
            transparent_bundle,
            sprout_bundle: unauthed_tx.sprout_bundle,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
            #[cfg(zcash_unstable = "nu7")]
            issue_bundle,
        };

        // The unwrap() here is safe because the txid hashing
        // of freeze() should be infalliable.
        Ok(BuildResult {
            transaction: authorized_tx.freeze().unwrap(),
            sapling_meta,
            orchard_meta,
            ironwood_meta,
        })
    }
}

impl<P: consensus::Parameters, U> Builder<P, U> {
    /// Builds a PCZT from the configured spends and outputs.
    ///
    /// Upon success, returns a struct containing the PCZT components, and the
    /// [`SaplingMetadata`] and [`orchard::builder::BundleMetadata`] generated during the
    /// build process.
    pub fn build_for_pczt<R: RngCore + CryptoRng, FR: FeeRule>(
        self,
        mut rng: R,
        fee_rule: &FR,
        #[cfg(zcash_unstable = "nu7")] is_new_asset: impl Fn(&AssetBase) -> bool,
    ) -> Result<PcztResult<P>, Error<FR::Error>> {
        let fee = self
            .get_fee(
                fee_rule,
                #[cfg(zcash_unstable = "nu7")]
                is_new_asset,
            )
            .map_err(Error::Fee)?;
        self.check_version_compatibility::<FR::Error>(self.tx_version)?;
        self.check_coinbase_expiry_height::<FR::Error>()?;

        //
        // Consistency checks
        //

        // After fees are accounted for, the value balance of the transaction must be zero.
        let balance_after_fees = (self.value_balance()? - fee).ok_or(BalanceError::Underflow)?;

        match balance_after_fees.cmp(&ZatBalance::zero()) {
            Ordering::Less => {
                return Err(Error::InsufficientFunds(-balance_after_fees));
            }
            Ordering::Greater => {
                return Err(Error::ChangeRequired(balance_after_fees));
            }
            Ordering::Equal => (),
        };

        let transparent_bundle = self.transparent_builder.build_for_pczt();

        let (sapling_bundle, sapling_meta) = match self
            .sapling_builder
            .map(|builder| {
                builder
                    .build_for_pczt(&mut rng)
                    .map_err(Error::SaplingBuild)
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, SaplingMetadata::empty()),
        };

        let (orchard_bundle, orchard_meta) = match self
            .orchard_builder
            .map(|builder| {
                builder
                    .build_for_pczt(&mut rng)
                    .map_err(Error::OrchardBuild)
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, orchard::builder::BundleMetadata::empty()),
        };

        // The Ironwood bundle is only carried by V6 transactions; for any other version it is
        // left empty (and `check_version_compatibility` above rejects an in-use Ironwood
        // builder paired with a non-V6 version).
        let (ironwood_bundle, ironwood_meta) = if self.tx_version.has_ironwood() {
            match self
                .ironwood_builder
                .map(|builder| {
                    builder
                        .build_for_pczt(&mut rng)
                        .map_err(Error::IronwoodBuild)
                })
                .transpose()?
            {
                Some((bundle, meta)) => (Some(bundle), meta),
                None => (None, orchard::builder::BundleMetadata::empty()),
            }
        } else {
            (None, orchard::builder::BundleMetadata::empty())
        };

        Ok(PcztResult {
            pczt_parts: PcztParts {
                params: self.params,
                version: self.tx_version,
                consensus_branch_id: self.consensus_branch_id,
                lock_time: 0,
                expiry_height: self.expiry_height,
                transparent: transparent_bundle,
                sapling: sapling_bundle,
                orchard: orchard_bundle,
                ironwood: ironwood_bundle,
            },
            sapling_meta,
            orchard_meta,
            ironwood_meta,
        })
    }
}

/// The nullifier that seeds issuance note randomness: the first action of the ZSA bundle, which
/// a v7 transaction carries in its Ironwood slot.
#[cfg(zcash_unstable = "nu7")]
fn first_nullifier<A: bundle::Authorization>(
    ironwood_bundle: &Option<orchard::Bundle<A, ZatBalance>>,
) -> Option<&Nullifier> {
    ironwood_bundle
        .as_ref()
        .filter(|b| b.bundle_version() == orchard::bundle::BundleVersion::zsa())
        .map(|b| b.actions().first().nullifier())
}

#[cfg(feature = "circuits")]
fn authorize_transparent(
    b: &transparent::bundle::Bundle<transparent::builder::Unauthorized>,
    unauthed_tx: &TransactionData<Unauthorized>,
    txid_parts: &TxDigests<blake2b_simd::Hash>,
    transparent_signing_set: &TransparentSigningSet,
) -> Result<transparent::bundle::Bundle<transparent::bundle::Authorized>, transparent::builder::Error>
{
    b.clone().apply_signatures(
        |input| {
            *signature_hash(unauthed_tx, &SignableInput::Transparent(input), txid_parts).as_ref()
        },
        transparent_signing_set,
    )
}

#[cfg(all(any(test, feature = "test-dependencies"), feature = "circuits"))]
mod testing {
    use rand_core::{CryptoRng, RngCore};

    use ::sapling::prover::mock::{MockOutputProver, MockSpendProver};
    use ::transparent::builder::TransparentSigningSet;
    use zcash_protocol::consensus;

    use super::{BuildResult, Builder, Error};
    use crate::transaction::fees::zip317;

    impl<P: consensus::Parameters, U: sapling::builder::ProverProgress> Builder<P, U> {
        /// Build the transaction using mocked randomness and proving capabilities.
        /// DO NOT USE EXCEPT FOR UNIT TESTING.
        pub fn mock_build<R: RngCore>(
            self,
            transparent_signing_set: &TransparentSigningSet,
            sapling_extsks: &[sapling::zip32::ExtendedSpendingKey],
            orchard_saks: &[orchard::keys::SpendAuthorizingKey],
            #[cfg(zcash_unstable = "nu7")] is_new_asset: impl Fn(&orchard::note::AssetBase) -> bool,
            rng: R,
        ) -> Result<BuildResult, Error<zip317::FeeError>> {
            struct FakeCryptoRng<R: RngCore>(R);
            impl<R: RngCore> CryptoRng for FakeCryptoRng<R> {}
            impl<R: RngCore> RngCore for FakeCryptoRng<R> {
                fn next_u32(&mut self) -> u32 {
                    self.0.next_u32()
                }

                fn next_u64(&mut self) -> u64 {
                    self.0.next_u64()
                }

                fn fill_bytes(&mut self, dest: &mut [u8]) {
                    self.0.fill_bytes(dest)
                }

                fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                    self.0.try_fill_bytes(dest)
                }
            }

            self.build(
                transparent_signing_set,
                sapling_extsks,
                orchard_saks,
                FakeCryptoRng(rng),
                &MockSpendProver,
                &MockOutputProver,
                #[allow(deprecated)]
                &zip317::FeeRule::standard(),
                #[cfg(zcash_unstable = "nu7")]
                is_new_asset,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "circuits")]
    use {
        super::{Builder, Error},
        crate::transaction::builder::BuildConfig,
        ::sapling::{Node, Rseed, zip32::ExtendedSpendingKey},
        ::transparent::{address::TransparentAddress, builder::TransparentSigningSet},
        assert_matches::assert_matches,
        core::convert::Infallible,
        ff::Field,
        incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness},
        rand_core::OsRng,
        zcash_protocol::{
            consensus::{NetworkUpgrade, Parameters, TEST_NETWORK},
            memo::MemoBytes,
            value::{BalanceError, ZatBalance, Zatoshis},
        },
    };

    #[cfg(zcash_unstable = "nu7")]
    #[cfg(not(feature = "transparent-inputs"))]
    use zip32::AccountId;

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::transaction::{OutPoint, TxOut, TxVersion, builder::DEFAULT_TX_EXPIRY_DELTA},
        ::transparent::keys::{AccountPrivKey, IncomingViewingKey},
        zcash_protocol::consensus::BranchId,
        zip32::AccountId,
    };

    #[cfg(zcash_unstable = "nu7")]
    use {
        crate::transaction::fees::zip317,
        nonempty::NonEmpty,
        orchard::{
            bundle::BundleVersion,
            issuance::auth::{IssueAuthKey, IssueValidatingKey},
            issuance::{IssueInfo, compute_asset_desc_hash},
            keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
            note::{AssetBase, AssetId},
            note_encryption::{NoteEncryptionDomain, ZSAVersion},
            tree::MerkleHashOrchard,
            value::NoteValue,
        },
        shardtree::{ShardTree, store::memory::MemoryShardStore},
        zcash_note_encryption::try_note_decryption,
        zcash_protocol::memo::Memo,
    };

    /// This is a helper function for testing that indicates no assets are newly created.
    #[cfg(zcash_unstable = "nu7")]
    fn no_new_assets(_: &AssetBase) -> bool {
        false
    }

    // The Ironwood tests below reference `TxVersion`/`BranchId` directly; without the
    // `transparent-inputs` feature these are not otherwise in scope.
    #[cfg(all(feature = "circuits", not(feature = "transparent-inputs")))]
    use {crate::transaction::TxVersion, zcash_protocol::consensus::BranchId};

    #[cfg(feature = "circuits")]
    fn nu6_3_test_network() -> zcash_protocol::local_consensus::LocalNetwork {
        use zcash_protocol::consensus::BlockHeight;

        zcash_protocol::local_consensus::LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(2)),
            blossom: Some(BlockHeight::from_u32(3)),
            heartwood: Some(BlockHeight::from_u32(4)),
            canopy: Some(BlockHeight::from_u32(5)),
            nu5: Some(BlockHeight::from_u32(6)),
            nu6: Some(BlockHeight::from_u32(7)),
            nu6_1: Some(BlockHeight::from_u32(8)),
            nu6_2: Some(BlockHeight::from_u32(9)),
            nu6_3: Some(BlockHeight::from_u32(10)),
            #[cfg(zcash_unstable = "nu7")]
            nu7: None,
        }
    }

    #[cfg(all(feature = "circuits", zcash_unstable = "nu7"))]
    fn nu7_test_network() -> zcash_protocol::local_consensus::LocalNetwork {
        use zcash_protocol::consensus::BlockHeight;

        zcash_protocol::local_consensus::LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(2)),
            blossom: Some(BlockHeight::from_u32(3)),
            heartwood: Some(BlockHeight::from_u32(4)),
            canopy: Some(BlockHeight::from_u32(5)),
            nu5: Some(BlockHeight::from_u32(6)),
            nu6: Some(BlockHeight::from_u32(7)),
            nu6_1: Some(BlockHeight::from_u32(8)),
            nu6_2: Some(BlockHeight::from_u32(9)),
            nu6_3: Some(BlockHeight::from_u32(10)),
            nu7: Some(BlockHeight::from_u32(11)),
        }
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu6_3_standard_builder_uses_v6_orchard_protocol() {
        let builder = Builder::new(
            nu6_3_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(10),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
        );

        assert_eq!(builder.tx_version, crate::transaction::TxVersion::V6);
        assert_eq!(
            builder.orchard_bundle_version,
            Some(orchard::bundle::BundleVersion::orchard_v3())
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu6_3_standard_builder_preserves_branch_orchard_protocol_for_explicit_v5() {
        let mut builder = Builder::new(
            nu6_3_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(10),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
        );

        builder
            .propose_version::<Infallible>(crate::transaction::TxVersion::V5)
            .unwrap();

        assert_eq!(
            builder.orchard_bundle_version,
            Some(orchard::bundle::BundleVersion::orchard_v3())
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu6_3_coinbase_builder_does_not_expose_orchard() {
        let builder = Builder::new(
            nu6_3_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(10),
            BuildConfig::Coinbase { miner_data: None },
        );

        assert!(builder.orchard_builder.is_none());
    }

    #[test]
    #[cfg(all(feature = "circuits", zcash_unstable = "nu7"))]
    fn nu7_coinbase_builder_does_not_expose_orchard() {
        let builder = Builder::new(
            nu7_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(11),
            BuildConfig::Coinbase { miner_data: None },
        );

        assert!(builder.orchard_builder.is_none());
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu6_3_coinbase_builder_uses_ironwood_not_orchard() {
        let builder = Builder::new(
            nu6_3_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(10),
            BuildConfig::Coinbase { miner_data: None },
        );

        assert!(builder.orchard_builder.is_none());
        assert_eq!(
            builder
                .ironwood_builder
                .as_ref()
                .map(|_| orchard::bundle::BundleVersion::ironwood_v3()),
            Some(orchard::bundle::BundleVersion::ironwood_v3())
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu6_3_coinbase_builder_has_ironwood_output_option() {
        let recipient = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap(),
        )
        .address_at(0u32, orchard::keys::Scope::External);
        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Coinbase { miner_data: None },
        );

        assert_matches!(
            builder.add_orchard_output::<Infallible>(
                None,
                recipient,
                Zatoshis::const_from_u64(10_000),
                orchard::note::AssetBase::zatoshi(),
                MemoBytes::empty(),
            ),
            Err(Error::OrchardBuilderNotAvailable)
        );

        builder
            .add_ironwood_output::<Infallible>(
                None,
                recipient,
                Zatoshis::const_from_u64(10_000),
                MemoBytes::empty(),
            )
            .unwrap();
        assert_eq!(
            builder.ironwood_builder.as_ref().map(|b| b.outputs().len()),
            Some(1)
        );
        assert_eq!(
            super::orchard_action_count(
                builder.ironwood_builder.as_ref().unwrap(),
                true,
                orchard::bundle::BundleVersion::ironwood_v3()
            )
            .unwrap(),
            1
        );
    }

    #[test]
    #[cfg(all(feature = "circuits", feature = "transparent-inputs"))]
    fn build_for_pczt_preserves_explicit_v6_without_ironwood() {
        use ::transparent::keys::NonHardenedChildIndex;

        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
        );
        builder
            .propose_version::<Infallible>(TxVersion::V6)
            .unwrap();

        let mut transparent_signing_set = TransparentSigningSet::new();
        let tsk = AccountPrivKey::from_seed(&TEST_NETWORK, &[0u8; 32], AccountId::ZERO).unwrap();
        let sk = tsk
            .derive_external_secret_key(NonHardenedChildIndex::ZERO)
            .unwrap();
        let pubkey = transparent_signing_set.add_key(sk);
        let prev_coin = TxOut::new(
            Zatoshis::const_from_u64(50000),
            tsk.to_account_pubkey()
                .derive_external_ivk()
                .unwrap()
                .derive_address(NonHardenedChildIndex::ZERO)
                .unwrap()
                .script()
                .into(),
        );

        builder
            .add_transparent_p2pkh_input(pubkey, OutPoint::fake(), prev_coin)
            .unwrap();
        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                Zatoshis::const_from_u64(40000),
            )
            .unwrap();

        let res = builder
            .build_for_pczt(
                OsRng,
                &crate::transaction::fees::zip317::FeeRule::standard(),
                #[cfg(zcash_unstable = "nu7")]
                |_| false,
            )
            .unwrap();
        assert_eq!(res.pczt_parts.version, TxVersion::V6);
        assert_eq!(
            res.pczt_parts.consensus_branch_id,
            zcash_protocol::consensus::BranchId::Nu6_3
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn build_for_pczt_accepts_v6_when_ironwood_is_used() {
        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
        );
        let recipient = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap(),
        )
        .address_at(0u32, orchard::keys::Scope::External);
        builder
            .add_ironwood_output::<crate::transaction::fees::zip317::FeeRule>(
                None,
                recipient,
                Zatoshis::const_from_u64(10_000),
                MemoBytes::empty(),
            )
            .unwrap();

        assert_matches!(
            builder.build_for_pczt(
                OsRng,
                &crate::transaction::fees::zip317::FeeRule::standard(),
                #[cfg(zcash_unstable = "nu7")]
                |_| false,
            ),
            Err(Error::InsufficientFunds(_))
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn build_for_pczt_rejects_explicit_v5_when_ironwood_is_used() {
        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
        );
        builder
            .propose_version::<Infallible>(TxVersion::V5)
            .unwrap();

        let recipient = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap(),
        )
        .address_at(0u32, orchard::keys::Scope::External);
        builder
            .add_ironwood_output::<crate::transaction::fees::zip317::FeeRule>(
                None,
                recipient,
                Zatoshis::const_from_u64(10_000),
                MemoBytes::empty(),
            )
            .unwrap();

        assert_matches!(
            builder.build_for_pczt(
                OsRng,
                &crate::transaction::fees::zip317::FeeRule::standard(),
                #[cfg(zcash_unstable = "nu7")]
                |_| false,
            ),
            Err(Error::TargetIncompatible(
                BranchId::Nu6_3,
                TxVersion::V5,
                None
            ))
        );
    }

    /// Test helper: returns a full viewing key, an Orchard note carrying the given
    /// note plaintext `version`, and a dummy Merkle path, for exercising the
    /// Ironwood builder's note-version handling.
    #[cfg(feature = "circuits")]
    fn ironwood_note_with_version(
        version: orchard::note::NoteVersion,
    ) -> (
        orchard::keys::FullViewingKey,
        orchard::Note,
        orchard::tree::MerklePath,
    ) {
        let sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
        let value = orchard::value::NoteValue::from_raw(99);
        let rho = orchard::note::Rho::from_bytes(&[1; 32]).unwrap();
        let rseed = (0u8..=255)
            .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
            .expect("at least one test rseed is valid");
        let note = orchard::Note::from_parts(
            recipient,
            value,
            orchard::note::AssetBase::zatoshi(),
            rho,
            rseed,
            version,
        )
        .unwrap();
        let zero = orchard::tree::MerkleHashOrchard::from_bytes(&[0; 32]).unwrap();
        let merkle_path = orchard::tree::MerklePath::from_parts(0, [zero; 32]);

        (fvk, note, merkle_path)
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn note_commitment_and_nullifier_depend_on_note_version() {
        let (fvk, v2_note, _) = ironwood_note_with_version(orchard::note::NoteVersion::V2);
        let (_, v3_note, _) = ironwood_note_with_version(orchard::note::NoteVersion::V3);

        // The notes share every field except the note plaintext version (lead byte
        // 0x02 vs 0x03), which must domain-separate both the commitment and the
        // nullifier.
        assert_ne!(
            orchard::note::ExtractedNoteCommitment::from(v2_note.commitment()).to_bytes(),
            orchard::note::ExtractedNoteCommitment::from(v3_note.commitment()).to_bytes(),
        );
        assert_ne!(
            v2_note.nullifier(&fvk).to_bytes(),
            v3_note.nullifier(&fvk).to_bytes(),
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn add_ironwood_spend_rejects_v2_note_version() {
        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
        );
        let (fvk, note, merkle_path) = ironwood_note_with_version(orchard::note::NoteVersion::V2);

        assert_matches!(
            builder.add_ironwood_spend::<Infallible>(fvk, note, merkle_path),
            Err(Error::IronwoodSpendUnsupportedNoteVersion(
                orchard::note::NoteVersion::V2
            ))
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn orchard_action_count_uses_cross_address_disabled_count() {
        let spend_sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
        let spend_fvk = orchard::keys::FullViewingKey::from(&spend_sk);
        let spend_recipient = spend_fvk.address_at(0u32, orchard::keys::Scope::External);
        let rho = orchard::note::Rho::from_bytes(&[1; 32]).unwrap();
        let rseed = (0u8..=255)
            .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
            .expect("at least one test rseed is valid");
        let note = orchard::Note::from_parts(
            spend_recipient,
            orchard::value::NoteValue::from_raw(10_000),
            orchard::note::AssetBase::zatoshi(),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        )
        .unwrap();
        let leaf = orchard::tree::MerkleHashOrchard::from_cmx(&note.commitment().into());
        let mut tree = CommitmentTree::<orchard::tree::MerkleHashOrchard, 32>::empty();
        tree.append(leaf).unwrap();
        let witness = IncrementalWitness::from_tree(tree).unwrap();
        let anchor = witness.root().into();
        let merkle_path = witness.path().unwrap().into();

        let mut builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            orchard::bundle::BundleVersion::orchard_v3(),
            orchard::bundle::BundleVersion::orchard_v3().default_flags(),
            anchor,
        )
        .unwrap();

        builder.add_spend(spend_fvk, note, merkle_path).unwrap();

        for seed in [[8u8; 32], [9u8; 32]] {
            let change_fvk = orchard::keys::FullViewingKey::from(
                &orchard::keys::SpendingKey::from_bytes(seed).unwrap(),
            );
            let recipient = change_fvk.address_at(0u32, orchard::keys::Scope::Internal);
            builder
                .add_change_output(
                    change_fvk,
                    None,
                    recipient,
                    orchard::value::NoteValue::from_raw(1_000),
                    orchard::note::AssetBase::zatoshi(),
                    [0u8; 512],
                )
                .unwrap();
        }

        assert_eq!(builder.spends().len(), 1);
        assert_eq!(builder.changes().len(), 2);
        assert_eq!(
            super::orchard_action_count(
                &builder,
                false,
                orchard::bundle::BundleVersion::orchard_v3(),
            )
            .unwrap(),
            3
        );
    }

    /// `BuildConfig::Standard`'s `orchard_pool_bundle_type` controls padding: the
    /// padded default counts a single-output bundle as 2 actions, while
    /// `UNPADDED` counts exactly the requested single action.
    #[test]
    #[cfg(feature = "circuits")]
    fn orchard_pool_bundle_type_controls_padding() {
        let recipient = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap(),
        )
        .address_at(0u32, orchard::keys::Scope::External);

        let config_with = |bundle_type| BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_pool_bundle_type: bundle_type,
        };

        // `orchard_v2` here: the NU6.3 `orchard_v3` version disables cross-address
        // transfers, so a bare output cannot be added.
        let count_for = |bundle_type| {
            let config = config_with(bundle_type);
            let mut builder = config
                .orchard_builder(orchard::bundle::BundleVersion::orchard_v2())
                .unwrap();
            builder
                .add_output(
                    None,
                    recipient,
                    orchard::value::NoteValue::from_raw(10_000),
                    orchard::note::AssetBase::zatoshi(),
                    [0u8; 512],
                )
                .unwrap();
            super::orchard_action_count(
                &builder,
                false,
                orchard::bundle::BundleVersion::orchard_v2(),
            )
            .unwrap()
        };

        assert_eq!(count_for(orchard::builder::BundleType::DEFAULT), 2);
        assert_eq!(count_for(orchard::builder::BundleType::UNPADDED), 1);
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn add_orchard_change_output_records_change() {
        let target_height = TEST_NETWORK.activation_height(NetworkUpgrade::Nu5).unwrap();
        let mut builder = Builder::new(
            TEST_NETWORK,
            target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
        );
        let fvk = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap(),
        );
        let recipient = fvk.address_at(0u32, orchard::keys::Scope::Internal);

        builder
            .add_orchard_change_output::<Infallible>(
                fvk,
                None,
                recipient,
                Zatoshis::const_from_u64(5_000),
                MemoBytes::empty(),
            )
            .unwrap();

        assert_eq!(
            builder.orchard_builder.as_ref().map(|b| b.changes().len()),
            Some(1)
        );
    }

    // This test only works with the transparent_inputs feature because we have to
    // be able to create a tx with a valid balance, without using Sapling inputs.
    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn binding_sig_absent_if_no_shielded_spend_or_output() {
        use crate::transaction::builder::{self, TransparentBuilder};
        use ::transparent::{builder::TransparentSigningSet, keys::NonHardenedChildIndex};
        use zcash_protocol::consensus::NetworkUpgrade;

        let sapling_activation_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        // Create a builder with 0 fee, so we can construct t outputs
        let consensus_branch_id = BranchId::for_height(&TEST_NETWORK, sapling_activation_height);
        let mut builder = builder::Builder {
            params: TEST_NETWORK,
            tx_version: TxVersion::suggested_for_branch(consensus_branch_id),
            consensus_branch_id,
            build_config: BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
            target_height: sapling_activation_height,
            expiry_height: sapling_activation_height + DEFAULT_TX_EXPIRY_DELTA,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: Zatoshis::ZERO,
            transparent_builder: TransparentBuilder::empty(),
            sapling_builder: None,
            orchard_builder: None,
            orchard_bundle_version: None,
            ironwood_builder: None,
            #[cfg(zcash_unstable = "nu7")]
            issuance_builder: None,
            #[cfg(zcash_unstable = "nu7")]
            issuance_isk: None,
            _progress_notifier: (),
        };

        let mut transparent_signing_set = TransparentSigningSet::new();
        let tsk = AccountPrivKey::from_seed(&TEST_NETWORK, &[0u8; 32], AccountId::ZERO).unwrap();
        let sk = tsk
            .derive_external_secret_key(NonHardenedChildIndex::ZERO)
            .unwrap();
        let pubkey = transparent_signing_set.add_key(sk);
        let prev_coin = TxOut::new(
            Zatoshis::const_from_u64(50000),
            tsk.to_account_pubkey()
                .derive_external_ivk()
                .unwrap()
                .derive_address(NonHardenedChildIndex::ZERO)
                .unwrap()
                .script()
                .into(),
        );
        builder
            .add_transparent_p2pkh_input(pubkey, OutPoint::fake(), prev_coin)
            .unwrap();

        // Create a tx with only t output. No binding_sig should be present
        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                Zatoshis::const_from_u64(40000),
            )
            .unwrap();

        let res = builder
            .mock_build(
                &transparent_signing_set,
                &[],
                &[],
                #[cfg(zcash_unstable = "nu7")]
                no_new_assets,
                OsRng,
            )
            .unwrap();
        // No binding signature, because only t input and outputs
        assert!(res.transaction().sapling_bundle.is_none());
    }

    #[test]
    #[cfg(all(feature = "circuits", feature = "transparent-inputs"))]
    fn build_uses_overridden_expiry_height() {
        use ::transparent::keys::NonHardenedChildIndex;

        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();
        let build_config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        };
        let mut builder =
            Builder::new(TEST_NETWORK, tx_height, build_config).with_expiry_height(0u32.into());

        let mut transparent_signing_set = TransparentSigningSet::new();
        let tsk = AccountPrivKey::from_seed(&TEST_NETWORK, &[0u8; 32], AccountId::ZERO).unwrap();
        let sk = tsk
            .derive_external_secret_key(NonHardenedChildIndex::ZERO)
            .unwrap();
        let pubkey = transparent_signing_set.add_key(sk);
        let prev_coin = TxOut::new(
            Zatoshis::const_from_u64(50_000),
            tsk.to_account_pubkey()
                .derive_external_ivk()
                .unwrap()
                .derive_address(NonHardenedChildIndex::ZERO)
                .unwrap()
                .script()
                .into(),
        );
        builder
            .add_transparent_p2pkh_input(pubkey, OutPoint::fake(), prev_coin)
            .unwrap();
        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                Zatoshis::const_from_u64(40_000),
            )
            .unwrap();

        let res = builder
            .mock_build(
                &transparent_signing_set,
                &[],
                &[],
                #[cfg(zcash_unstable = "nu7")]
                |_| false,
                OsRng,
            )
            .unwrap();
        assert_eq!(res.transaction().expiry_height(), 0u32.into());
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn build_rejects_mismatched_coinbase_expiry_height() {
        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();
        let build_config = BuildConfig::Coinbase { miner_data: None };
        let mut builder =
            Builder::new(TEST_NETWORK, tx_height, build_config).with_expiry_height(0u32.into());

        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                Zatoshis::const_from_u64(50_000),
            )
            .unwrap();

        assert_matches!(
            builder.mock_build(
                &TransparentSigningSet::new(),
                &[],
                &[],
                #[cfg(zcash_unstable = "nu7")]
                |_| false,
                OsRng,
            ),
            Err(Error::CoinbaseExpiryHeightMismatch {
                target_height,
                expiry_height,
            }) if target_height == tx_height && expiry_height == 0u32.into()
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn binding_sig_present_if_shielded_spend() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1;

        let mut rng = OsRng;

        let note1 = to.create_note(
            sapling::value::NoteValue::from_raw(50000),
            Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
        );
        let cmu1 = Node::from_cmu(&note1.cmu());
        let mut tree = CommitmentTree::<Node, 32>::empty();
        tree.append(cmu1).unwrap();
        let witness1 = IncrementalWitness::from_tree(tree).unwrap();

        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        let build_config = BuildConfig::Standard {
            sapling_anchor: Some(witness1.root().into()),
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        };
        let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);

        // Create a tx with a sapling spend. binding_sig should be present
        builder
            .add_sapling_spend::<Infallible>(dfvk.fvk().clone(), note1, witness1.path().unwrap())
            .unwrap();

        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                Zatoshis::const_from_u64(35000),
            )
            .unwrap();

        // A binding signature (and bundle) is present because there is a Sapling spend.
        let res = builder
            .mock_build(
                &TransparentSigningSet::new(),
                &[extsk],
                &[],
                #[cfg(zcash_unstable = "nu7")]
                no_new_assets,
                OsRng,
            )
            .unwrap();
        assert!(res.transaction().sapling_bundle().is_some());
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn fails_on_negative_change() {
        use crate::transaction::fees::zip317::MINIMUM_FEE;

        let mut rng = OsRng;

        // Just use the master key as the ExtendedSpendingKey for this test
        let extsk = ExtendedSpendingKey::master(&[]);
        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        // Fails with no inputs or outputs
        // 0.0001 t-ZEC fee
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            };
            let builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            assert_matches!(
                builder.mock_build(
                    &TransparentSigningSet::new(),
                    &[],
                    &[],
                    #[cfg(zcash_unstable = "nu7")]
                    no_new_assets,
                    OsRng,
                ),
                Err(Error::InsufficientFunds(expected)) if expected == MINIMUM_FEE.into()
            );
        }

        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let ovk = Some(dfvk.fvk().ovk);
        let to = dfvk.default_address().1;

        let extsks = &[extsk];

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    Zatoshis::const_from_u64(50000),
                    MemoBytes::empty(),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    #[cfg(zcash_unstable = "nu7")]
                    no_new_assets,
                    OsRng
                ),
                Err(Error::InsufficientFunds(expected)) if
                    expected == (Zatoshis::const_from_u64(50000) + MINIMUM_FEE).unwrap().into()
            );
        }

        // Fail if there is only a transparent output
        // 0.0005 t-ZEC out, 0.0001 t-ZEC fee
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    Zatoshis::const_from_u64(50000),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    #[cfg(zcash_unstable = "nu7")]
                    no_new_assets,
                    OsRng
                ),
                Err(Error::InsufficientFunds(expected)) if expected ==
                    (Zatoshis::const_from_u64(50000) + MINIMUM_FEE).unwrap().into()
            );
        }

        // Fail if there is only a burn
        // 0.0005 burned, 0.0001 t-ZEC fee
        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder.set_zip233_amount(Zatoshis::const_from_u64(50000));

            assert_matches!(
                builder.mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    #[cfg(zcash_unstable = "nu7")]
                    no_new_assets,
                    OsRng
                ),
                Err(Error::InsufficientFunds(expected)) if expected ==
                    (Zatoshis::const_from_u64(50000) + MINIMUM_FEE).unwrap().into()
            );
        }

        let note1 = to.create_note(
            sapling::value::NoteValue::from_raw(59999),
            Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
        );
        let cmu1 = Node::from_cmu(&note1.cmu());
        let mut tree = CommitmentTree::<Node, 32>::empty();
        tree.append(cmu1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(tree.clone()).unwrap();

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.00015 t-ZEC out, 0.00015 t-ZEC fee, 0.00059999 z-ZEC in
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(witness1.root().into()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    Zatoshis::const_from_u64(30000),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    Zatoshis::const_from_u64(15000),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    #[cfg(zcash_unstable = "nu7")]
                    no_new_assets,
                    OsRng
                ),
                Err(Error::InsufficientFunds(expected)) if expected == ZatBalance::const_from_i64(1)
            );
        }

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.00005 t-ZEC out, 0.0001 burned, 0.00015 t-ZEC fee, 0.00059999 z-ZEC in
        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(witness1.root().into()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    Zatoshis::const_from_u64(30000),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    Zatoshis::const_from_u64(5000),
                )
                .unwrap();
            builder.set_zip233_amount(Zatoshis::const_from_u64(10000));
            assert_matches!(
                builder.mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    #[cfg(zcash_unstable = "nu7")]
                    no_new_assets,
                    OsRng
                ),
                Err(Error::InsufficientFunds(expected)) if expected == ZatBalance::const_from_i64(1)
            );
        }

        let note2 = to.create_note(
            sapling::value::NoteValue::from_raw(1),
            Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
        );
        let cmu2 = Node::from_cmu(&note2.cmu());
        tree.append(cmu2).unwrap();
        witness1.append(cmu2).unwrap();
        let witness2 = IncrementalWitness::from_tree(tree).unwrap();

        // Succeeds if there is sufficient input
        // 0.0003 z-ZEC out, 0.00015 t-ZEC out, 0.00015 t-ZEC fee, 0.0006 z-ZEC in
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(witness1.root().into()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note2.clone(),
                    witness2.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    Zatoshis::const_from_u64(30000),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    Zatoshis::const_from_u64(15000),
                )
                .unwrap();
            let res = builder
                .mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    #[cfg(zcash_unstable = "nu7")]
                    no_new_assets,
                    OsRng,
                )
                .unwrap();
            assert_eq!(
                res.transaction()
                    .fee_paid(|_| Err(BalanceError::Overflow))
                    .unwrap(),
                Some(Zatoshis::const_from_u64(15_000))
            );
        }

        // Succeeds if there is sufficient input
        // 0.0003 z-ZEC out, 0.00005 t-ZEC out, 0.0001 burned, 0.00015 t-ZEC fee, 0.0006 z-ZEC in
        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(witness1.root().into()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note1,
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note2,
                    witness2.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    Zatoshis::const_from_u64(30000),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    Zatoshis::const_from_u64(5000),
                )
                .unwrap();
            builder.set_zip233_amount(Zatoshis::const_from_u64(10000));
            let res = builder
                .mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    #[cfg(zcash_unstable = "nu7")]
                    no_new_assets,
                    OsRng,
                )
                .unwrap();
            assert_eq!(
                res.transaction()
                    .fee_paid(|_| Err(BalanceError::Overflow))
                    .unwrap(),
                Some(Zatoshis::const_from_u64(15_000))
            );
        }
    }

    // FIXME: rewritten for the v7 ZSA layout but never compiled or run. Two things to check:
    // the ZSA bundle is now built by the Ironwood builder, and `add_orchard_output` still takes an
    // asset while writing into the Orchard slot, so asset-carrying outputs have no v7 path yet.
    #[cfg(zcash_unstable = "nu7")]
    #[test]
    fn check_zsa_issuance_fees() {
        const OLD_NOTE_VALUE: u64 = 10_000_000;

        // The scenario in the test issues:
        // - one note of a previously issued asset (asset_desc_hash_1), and
        // - two notes of a newly created asset (asset_desc_hash_2): the first note is the
        //   reference note and the second note is another note of the same newly created asset.
        // The expected number of logical actions is:
        // - 2 Orchard Actions (the minimum required for an Orchard bundle),
        // - 3 issued notes in total,
        // - 1 * 100 for the contribution of the newly created asset.
        // The logical_actions is therefore 105, leading to a fee of 105 * 5_000 = 525_000 zatoshis.
        const EXPECTED_FEE: u64 = 525_000;

        let mut rng = OsRng;
        let tx_height = TEST_NETWORK.activation_height(NetworkUpgrade::Nu7).unwrap();

        // Generate keys
        let sk = SpendingKey::from_zip32_seed(&[1u8; 32], 1, AccountId::ZERO).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);
        let isk = IssueAuthKey::from_zip32_seed(&[1u8; 32], 1, 0).unwrap();
        let ik = IssueValidatingKey::from(&isk);

        // Create a test note in the Orchard tree
        let note = {
            let bundle_version = BundleVersion::zsa();
            let mut builder = orchard::builder::Builder::new(
                orchard::builder::BundleType::DEFAULT,
                bundle_version,
                bundle_version.default_flags(),
                orchard::Anchor::empty_tree(),
            )
            .unwrap();
            builder
                .add_output(
                    None,
                    recipient,
                    NoteValue::from_raw(OLD_NOTE_VALUE),
                    AssetBase::zatoshi(),
                    Memo::Empty.encode().into_bytes(),
                )
                .unwrap();
            let (bundle, meta) = builder.build::<i64>(&mut rng).unwrap().unwrap();
            let action = bundle
                .actions()
                .get(meta.output_action_index(0).unwrap())
                .unwrap();
            let (note, _, _) = try_note_decryption(
                &NoteEncryptionDomain::<ZSAVersion>::for_action(action),
                &fvk.to_ivk(Scope::External).prepare(),
                action,
            )
            .unwrap();
            note
        };

        let (anchor, merkle_path) = {
            let leaf = MerkleHashOrchard::from_cmx(&note.commitment().into());
            let mut tree = ShardTree::<_, 32, 16>::new(
                MemoryShardStore::<MerkleHashOrchard, u32>::empty(),
                100,
            );
            tree.append(leaf, incrementalmerkletree::Retention::Marked)
                .unwrap();
            tree.checkpoint(9_999_999).unwrap();
            let path = tree
                .witness_at_checkpoint_depth(0.into(), 0)
                .unwrap()
                .unwrap();
            (path.root(leaf).into(), path.into())
        };

        let mut builder = Builder::new(
            TEST_NETWORK,
            tx_height,
            BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
        );

        // Define two assets: one previously issued, one newly created
        let asset_1 = compute_asset_desc_hash(&NonEmpty::from_slice(b"This is Asset 1").unwrap());
        let asset_2 = compute_asset_desc_hash(&NonEmpty::from_slice(b"This is Asset 2").unwrap());

        let prev_issued = AssetBase::custom(&AssetId::new_v0(&ik, &asset_1));
        let is_new_asset = move |asset: &AssetBase| asset != &prev_issued;

        // Add spend and output for fees
        builder
            .add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
            .unwrap();
        builder
            .add_ironwood_output::<zip317::FeeRule>(
                Some(fvk.to_ovk(Scope::External)),
                recipient,
                Zatoshis::from_u64(OLD_NOTE_VALUE - EXPECTED_FEE).unwrap(),
                MemoBytes::empty(),
            )
            .unwrap();

        // Issue previously issued asset and newly created asset
        builder
            .init_issuance_bundle::<zip317::FeeRule>(
                isk,
                asset_1,
                Some(IssueInfo {
                    recipient,
                    value: NoteValue::from_raw(1),
                }),
                false,
            )
            .unwrap();
        builder
            .add_recipient::<zip317::FeeRule>(asset_2, recipient, NoteValue::from_raw(1), true)
            .unwrap();

        let build_result = builder
            .mock_build(
                &TransparentSigningSet::new(),
                &[],
                &[SpendAuthorizingKey::from(&sk)],
                #[cfg(zcash_unstable = "nu7")]
                is_new_asset,
                OsRng,
            )
            .unwrap();
        let tx = build_result.transaction();

        // Verify: 2 Ironwood actions, 3 issued notes,
        // fee = 5000 * (2 + 3 + 100) = 525_000 (as in the EXPECTED_FEE calculation above).
        assert_eq!(tx.ironwood_bundle().unwrap().actions().len(), 2);
        assert_eq!(tx.issue_bundle().unwrap().get_all_notes().len(), 3);
        assert_eq!(
            tx.fee_paid(|_| Err(BalanceError::Overflow)).unwrap(),
            Some(Zatoshis::const_from_u64(EXPECTED_FEE))
        );
    }
}
