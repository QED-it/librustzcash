//! Functions for parsing & serialization of Orchard transaction components.
use crate::encoding::ReadBytesExt;

#[cfg(zcash_unstable = "nu7")]
use {
    crate::{
        encoding::WriteBytesExt,
        sighash_versioning::{orchard_sighash_kind_from_info, orchard_sighash_kind_to_info},
        transaction::components::issuance::read_asset,
    },
    orchard::{note::AssetBase, value::NoteValue},
};

use alloc::vec::Vec;
use core::convert::TryFrom;
use corez::io::{self, Read, Write};

use nonempty::NonEmpty;

use orchard::{
    Action, Anchor, ValuePool,
    bundle::{Authorization, Authorized, BundleVersion, Flags},
    note::{ExtractedNoteCommitment, NoteVersion, Nullifier, TransmittedNoteCiphertext},
    note_encryption::{ENC_CIPHERTEXT_SIZE_VANILLA, ENC_CIPHERTEXT_SIZE_ZSA, NoteCiphertextBytes},
    primitives::redpallas::{self, SigType, Signature, SpendAuth, VerificationKey},
    sighash_kind::{OrchardSig, OrchardSighashKind},
    value::ValueCommitment,
};
use zcash_encoding::{Array, CompactSize, Vector};
use zcash_note_encryption::note_bytes::NoteBytes;
use zcash_protocol::{
    consensus::{BranchId, OrchardProtocolRevision},
    value::ZatBalance,
};

use crate::transaction::Transaction;

pub const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;
pub const FLAG_OUTPUTS_ENABLED: u8 = 0b0000_0010;
pub const FLAGS_EXPECTED_UNSET: u8 = !(FLAG_SPENDS_ENABLED | FLAG_OUTPUTS_ENABLED);

pub trait MapAuth<A: Authorization, B: Authorization> {
    fn map_spend_auth(&self, s: A::SpendAuth) -> B::SpendAuth;
    fn map_authorization(&self, a: A) -> B;
}

/// The identity map.
///
/// This can be used with [`TransactionData::map_authorization`] when you want to map the
/// authorization of a subset of the transaction's bundles.
///
/// [`TransactionData::map_authorization`]: crate::transaction::TransactionData::map_authorization
impl MapAuth<Authorized, Authorized> for () {
    fn map_spend_auth(
        &self,
        s: <Authorized as Authorization>::SpendAuth,
    ) -> <Authorized as Authorization>::SpendAuth {
        s
    }

    fn map_authorization(&self, a: Authorized) -> Authorized {
        a
    }
}

fn read_bundle<R: Read>(
    mut reader: R,
    bundle_version: Option<BundleVersion>,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    // Neither the Orchard nor the Ironwood pool uses ZSA-sized note ciphertexts.
    let note_version = bundle_version.map_or(NoteVersion::V2, |v| v.note_version());
    let actions_without_auth =
        Vector::read(&mut reader, |r| read_action_without_auth(r, note_version))?;
    if actions_without_auth.is_empty() {
        Ok(None)
    } else {
        let bundle_version = bundle_version.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Orchard-protocol bundles may not be present in this transaction version \
                 under the transaction's consensus branch ID",
            )
        })?;
        let flags = read_flags(&mut reader, bundle_version)?;
        let value_balance = Transaction::read_amount(&mut reader)?;
        let anchor = read_anchor(&mut reader)?;
        let proof_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
        let actions = NonEmpty::from_vec(
            actions_without_auth
                .into_iter()
                .map(|act| act.try_map(|_| read_signature::<_, redpallas::SpendAuth>(&mut reader)))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .expect("A nonzero number of actions was read from the transaction data.");
        let binding_signature = read_signature::<_, redpallas::Binding>(&mut reader)?;

        let authorization = orchard::bundle::Authorized::from_parts(
            orchard::Proof::new(proof_bytes),
            binding_signature,
        );

        // `try_from_parts` rejects a proof whose length is not the canonical size for the number
        // of actions, preventing a proof padded with arbitrary data (GHSA-2x4w-pxqw-58v9). Proof
        // size is enforced for every version except the historical pre-NU6.2 Orchard pool
        // ([`BundleVersion::orchard_insecure_v1`]); see the `bundle_version` chosen by the caller.
        orchard::Bundle::try_from_parts(
            actions,
            flags,
            value_balance,
            vec![],
            anchor,
            authorization,
            bundle_version,
        )
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Returns the [`BundleVersion`] in effect for the given Orchard-protocol value pool
/// under the given consensus branch, or `None` if the pool is not supported under that
/// branch (the Orchard pool prior to NU5; the Ironwood pool prior to NU6.3).
///
/// The protocol revision is determined by
/// [`BranchId::orchard_protocol_revision`]. The `BundleVersion` fixes a bundle's
/// flag-byte grammar, cross-address semantics, and circuit generation:
///   * Orchard pool, NU5 through NU6.1: historical insecure circuit, cross-address
///     enabled, proof size not enforced;
///   * Orchard pool, NU6.2: fixed circuit, cross-address enabled;
///   * Orchard pool, NU6.3 onward: post-NU6.3 circuit, cross-address disabled
///     (consensus-mandated);
///   * Ironwood pool, NU6.3 onward: post-NU6.3 circuit, cross-address enabled.
pub fn bundle_version_for_branch(
    consensus_branch_id: BranchId,
    pool: ValuePool,
) -> Option<BundleVersion> {
    let revision = consensus_branch_id.orchard_protocol_revision()?;
    match pool {
        ValuePool::Orchard => Some(match revision {
            OrchardProtocolRevision::InsecureV1 => BundleVersion::orchard_insecure_v1(),
            OrchardProtocolRevision::V2 => BundleVersion::orchard_v2(),
            OrchardProtocolRevision::V3 => BundleVersion::orchard_v3(),
        }),
        ValuePool::Ironwood => match revision {
            OrchardProtocolRevision::InsecureV1 | OrchardProtocolRevision::V2 => None,
            OrchardProtocolRevision::V3 => Some(BundleVersion::ironwood_v3()),
        },
    }
}

/// Reads an [`orchard::Bundle`] from a v5 transaction format.
///
/// The v5 Orchard wire serialization is identical in every epoch (flag bit 2 is
/// reserved), but the returned bundle's [`BundleVersion`] — which fixes its
/// cross-address semantics and circuit generation — follows the consensus epoch
/// identified by `consensus_branch_id` (see [`bundle_version_for_branch`]). A
/// non-empty Orchard bundle under a consensus branch that predates NU5 is
/// rejected as invalid data.
pub fn read_v5_bundle<R: Read>(
    reader: R,
    consensus_branch_id: BranchId,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    read_bundle(
        reader,
        bundle_version_for_branch(consensus_branch_id, ValuePool::Orchard),
    )
}

/// Rejects bundle versions that are not valid for the v6 transaction format, which has exactly
/// two Orchard-bundle slots: the Orchard slot ([`BundleVersion::orchard_v3`]) and the Ironwood
/// slot ([`BundleVersion::ironwood_v3`]). A pre-NU6.3 version would (de)serialize the flag byte
/// with the wrong cross-address (bit 2) semantics.
fn check_v6_bundle_version(bundle_version: BundleVersion) -> io::Result<()> {
    if bundle_version == BundleVersion::orchard_v3()
        || bundle_version == BundleVersion::ironwood_v3()
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "v6 Orchard bundles require orchard_v3 or ironwood_v3",
        ))
    }
}

/// Reads an [`orchard::Bundle`] from a v6 transaction format. `pool` selects the bundle
/// slot to read: the Orchard slot ([`ValuePool::Orchard`]) or the Ironwood slot
/// ([`ValuePool::Ironwood`], whose flag-byte encoding permits the cross-address bit,
/// unlike the Orchard v6 pool). The slot's [`BundleVersion`] is derived from
/// `consensus_branch_id` (see [`bundle_version_for_branch`]); a non-empty bundle in a
/// slot whose value pool is not supported under the transaction's consensus branch is
/// rejected as invalid data.
pub fn read_v6_bundle<R: Read>(
    reader: R,
    consensus_branch_id: BranchId,
    pool: ValuePool,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    read_bundle(reader, bundle_version_for_branch(consensus_branch_id, pool))
}

/// Rejects bundle versions that are not valid for the v7 transaction format, whose Ironwood slot
/// always carries the ZSA bundle ([`BundleVersion::zsa`]). The version is fixed by the transaction
/// version rather than by the consensus branch, because v6 remains valid in the same branch.
#[cfg(zcash_unstable = "nu7")]
fn check_v7_bundle_version(bundle_version: BundleVersion) -> io::Result<()> {
    if bundle_version == BundleVersion::zsa() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "v7 Ironwood bundles require the ZSA bundle version",
        ))
    }
}

/// Reads the Ironwood ZSA [`orchard::Bundle`] of a v7 transaction.
#[cfg(zcash_unstable = "nu7")]
pub fn read_v7_bundle<R: Read>(
    mut reader: R,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    let num_action_groups = CompactSize::read(&mut reader)?;
    if num_action_groups == 0 {
        return Ok(None);
    }

    // FIXME: v7 allows several action groups, but `orchard::Bundle` can hold only one until the
    // swaps work (QED-it/orchard PR #268) is rebased onto the flat-bundle API.
    if num_action_groups > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Multiple action groups are not supported yet",
        ));
    }

    let actions_without_auth = Vector::read(&mut reader, |r| {
        read_action_without_auth(r, NoteVersion::ZSA)
    })?;
    if actions_without_auth.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "An action group must contain at least one action",
        ));
    }
    let flags = read_flags(&mut reader, BundleVersion::zsa())?;
    let anchor = read_anchor(&mut reader)?;
    let n_ag_expiry_height = reader.read_u32_le()?;
    if n_ag_expiry_height != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nAGExpiryHeight field must be set to zero",
        ));
    }
    let burn = read_burn(&mut reader)?;
    let proof_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    let actions = NonEmpty::from_vec(
        actions_without_auth
            .into_iter()
            .map(|action| {
                action.try_map(|_| read_versioned_signature::<_, redpallas::SpendAuth>(&mut reader))
            })
            .collect::<Result<Vec<_>, _>>()?,
    )
    .ok_or(io::Error::new(
        io::ErrorKind::InvalidInput,
        "The action group must contain at least one action.",
    ))?;

    let value_balance = Transaction::read_amount(&mut reader)?;

    let binding_signature = read_versioned_signature::<_, redpallas::Binding>(&mut reader)?;

    let authorization = Authorized::from_parts(orchard::Proof::new(proof_bytes), binding_signature);

    orchard::Bundle::try_from_parts(
        actions,
        flags,
        value_balance,
        burn,
        anchor,
        authorization,
        BundleVersion::zsa(),
    )
    .map(Some)
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Reads burn for OrchardZSA
#[cfg(zcash_unstable = "nu7")]
pub fn read_burn<R: Read>(mut reader: &mut R) -> io::Result<Vec<(AssetBase, NoteValue)>> {
    Vector::read(&mut reader, read_burn_item)
}

#[cfg(zcash_unstable = "nu7")]
fn read_burn_item<R: Read>(reader: &mut R) -> io::Result<(AssetBase, NoteValue)> {
    Ok((read_asset(reader)?, read_note_value(reader)?))
}

pub fn read_value_commitment<R: Read>(mut reader: R) -> io::Result<ValueCommitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let cv = ValueCommitment::from_bytes(&bytes);

    if cv.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas point for value commitment",
        ))
    } else {
        Ok(cv.unwrap())
    }
}

pub fn read_nullifier<R: Read>(mut reader: R) -> io::Result<Nullifier> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let nullifier_ctopt = Nullifier::from_bytes(&bytes);
    if nullifier_ctopt.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas point for nullifier",
        ))
    } else {
        Ok(nullifier_ctopt.unwrap())
    }
}

pub fn read_verification_key<R: Read>(mut reader: R) -> io::Result<VerificationKey<SpendAuth>> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    VerificationKey::try_from(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid verification key"))
}

pub fn read_cmx<R: Read>(mut reader: R) -> io::Result<ExtractedNoteCommitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let cmx = ExtractedNoteCommitment::from_bytes(&bytes);
    Option::from(cmx).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas base for field cmx",
        )
    })
}

pub fn read_note_ciphertext<R: Read>(
    mut reader: R,
    note_version: NoteVersion,
) -> io::Result<TransmittedNoteCiphertext> {
    let mut epk_bytes = [0u8; 32];
    let mut enc_ciphertext = vec![
        0u8;
        match note_version {
            NoteVersion::ZSA => ENC_CIPHERTEXT_SIZE_ZSA,
            _ => ENC_CIPHERTEXT_SIZE_VANILLA,
        }
    ];
    let mut out_ciphertext = [0u8; 80];

    reader.read_exact(&mut epk_bytes)?;
    reader.read_exact(&mut enc_ciphertext)?;
    reader.read_exact(&mut out_ciphertext)?;

    Ok(TransmittedNoteCiphertext {
        epk_bytes,
        enc_ciphertext: NoteCiphertextBytes::from_slice(&enc_ciphertext)
            .expect("buffer has one of the two canonical ciphertext sizes"),
        out_ciphertext,
    })
}

pub fn read_action_without_auth<R: Read>(
    mut reader: R,
    note_version: NoteVersion,
) -> io::Result<Action<()>> {
    let cv_net = read_value_commitment(&mut reader)?;
    let nf_old = read_nullifier(&mut reader)?;
    let rk = read_verification_key(&mut reader)?;
    let cmx = read_cmx(&mut reader)?;
    let encrypted_note = read_note_ciphertext(&mut reader, note_version)?;

    Action::from_parts(nf_old, rk, cmx, encrypted_note, cv_net, ())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn read_flags<R: Read>(mut reader: R, bundle_version: BundleVersion) -> io::Result<Flags> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Flags::from_byte(byte[0], bundle_version)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid Orchard flags"))
}

pub fn read_anchor<R: Read>(mut reader: R) -> io::Result<Anchor> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(Anchor::from_bytes(bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid Orchard anchor"))
}

pub fn read_signature<R: Read, T: SigType>(mut reader: R) -> io::Result<OrchardSig<T>> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(OrchardSig::new(
        OrchardSighashKind::AllEffecting,
        Signature::from(bytes),
    ))
}

#[cfg(zcash_unstable = "nu7")]
fn read_versioned_signature<R: Read, T: SigType>(mut reader: R) -> io::Result<OrchardSig<T>> {
    let sighash_info_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    let sighash_kind =
        orchard_sighash_kind_from_info(sighash_info_bytes.as_slice()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Unknown Orchard sighash info")
        })?;

    let mut signature_bytes = [0u8; 64];
    reader.read_exact(&mut signature_bytes)?;
    Ok(OrchardSig::new(
        sighash_kind,
        Signature::from(signature_bytes),
    ))
}

#[cfg(zcash_unstable = "nu7")]
fn write_versioned_signature<W: Write, T: SigType>(
    mut writer: W,
    versioned_sig: &OrchardSig<T>,
) -> io::Result<()> {
    let sighash_info_bytes = orchard_sighash_kind_to_info(versioned_sig.sighash_kind());
    Vector::write(&mut writer, &sighash_info_bytes, |w, b| w.write_u8(*b))?;
    writer.write_all(&<[u8; 64]>::from(versioned_sig.sig()))
}

fn write_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    mut writer: W,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        Vector::write_nonempty(&mut writer, bundle.actions(), |w, a| {
            write_action_without_auth(w, a)
        })?;

        // The flag byte is encoded under the bundle's own `BundleVersion`, which is infallible:
        // a `Bundle` is only ever constructed with flags representable under its version.
        writer.write_all(&[bundle.flag_byte()])?;
        writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;
        writer.write_all(&bundle.anchor().to_bytes())?;
        Vector::write(
            &mut writer,
            bundle.authorization().proof().as_ref(),
            |w, b| w.write_all(&[*b]),
        )?;
        Array::write(
            &mut writer,
            bundle.actions().iter().map(|a| a.authorization().sig()),
            |w, auth| w.write_all(&<[u8; 64]>::from(*auth)),
        )?;
        writer.write_all(&<[u8; 64]>::from(
            bundle.authorization().binding_signature().sig(),
        ))?;
    } else {
        CompactSize::write(&mut writer, 0)?;
    }

    Ok(())
}

#[cfg(zcash_unstable = "nu7")]
fn read_note_value<R: Read>(mut reader: R) -> io::Result<NoteValue> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(NoteValue::from_bytes(bytes))
}

/// Writes burn for OrchardZSA
#[cfg(zcash_unstable = "nu7")]
pub fn write_burn<W: Write>(writer: &mut W, burn: &[(AssetBase, NoteValue)]) -> io::Result<()> {
    Vector::write(writer, burn, |w, (asset, amount)| {
        w.write_all(&asset.to_bytes())?;
        w.write_all(&amount.to_bytes())?;
        Ok(())
    })?;
    Ok(())
}

/// Writes an [`orchard::Bundle`] in the v5 transaction format.
///
/// The Orchard flag byte is encoded under the bundle's own [`BundleVersion`]; an Orchard bundle
/// never sets the cross-address bit, so its byte is always valid for the v5 format.
pub fn write_v5_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    writer: W,
) -> io::Result<()> {
    write_bundle(bundle, writer)
}

/// Writes an [`orchard::Bundle`] in the v6 transaction format. The bundle's own
/// [`BundleVersion`] selects the pool (and hence the flag-byte grammar): the Orchard slot uses
/// [`BundleVersion::orchard_v3`], the Ironwood slot [`BundleVersion::ironwood_v3`].
pub fn write_v6_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    writer: W,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        check_v6_bundle_version(bundle.bundle_version())?;
    }
    write_bundle(bundle, writer)
}

/// Writes the Ironwood ZSA [`orchard::Bundle`] of a v7 transaction.
#[cfg(zcash_unstable = "nu7")]
pub fn write_v7_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    mut writer: W,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        check_v7_bundle_version(bundle.bundle_version())?;

        // FIXME: one action group until `orchard::Bundle` can hold several (see `read_v7_bundle`).
        CompactSize::write(&mut writer, 1)?;

        Vector::write_nonempty(&mut writer, bundle.actions(), |w, a| {
            write_action_without_auth(w, a)
        })?;

        writer.write_all(&[bundle.flag_byte()])?;
        writer.write_all(&bundle.anchor().to_bytes())?;

        // nAGExpiryHeight must be zero for NU7
        writer.write_u32_le(0)?;

        write_burn(&mut writer, bundle.burn())?;

        Vector::write(
            &mut writer,
            bundle.authorization().proof().as_ref(),
            |w, b| w.write_u8(*b),
        )?;

        Array::write(
            &mut writer,
            bundle.actions().iter().map(|a| a.authorization()),
            |w, auth| write_versioned_signature(w, auth),
        )?;

        writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;

        write_versioned_signature(&mut writer, bundle.authorization().binding_signature())?;
    } else {
        CompactSize::write(&mut writer, 0)?;
    }

    Ok(())
}

pub fn write_value_commitment<W: Write>(mut writer: W, cv: &ValueCommitment) -> io::Result<()> {
    writer.write_all(&cv.to_bytes())
}

pub fn write_nullifier<W: Write>(mut writer: W, nf: &Nullifier) -> io::Result<()> {
    writer.write_all(&nf.to_bytes())
}

pub fn write_verification_key<W: Write>(
    mut writer: W,
    rk: &redpallas::VerificationKey<SpendAuth>,
) -> io::Result<()> {
    writer.write_all(&<[u8; 32]>::from(rk))
}

pub fn write_cmx<W: Write>(mut writer: W, cmx: &ExtractedNoteCommitment) -> io::Result<()> {
    writer.write_all(&cmx.to_bytes())
}

pub fn write_note_ciphertext<W: Write>(
    mut writer: W,
    nc: &TransmittedNoteCiphertext,
) -> io::Result<()> {
    writer.write_all(&nc.epk_bytes)?;
    writer.write_all(nc.enc_ciphertext.as_ref())?;
    writer.write_all(&nc.out_ciphertext)
}

pub fn write_action_without_auth<W: Write>(
    mut writer: W,
    act: &Action<<Authorized as Authorization>::SpendAuth>,
) -> io::Result<()> {
    write_value_commitment(&mut writer, act.cv_net())?;
    write_nullifier(&mut writer, act.nullifier())?;
    write_verification_key(&mut writer, act.rk())?;
    write_cmx(&mut writer, act.cmx())?;
    write_note_ciphertext(&mut writer, act.encrypted_note())?;
    Ok(())
}

#[cfg(all(test, zcash_unstable = "nu7"))]
mod tests {
    use {
        super::{read_versioned_signature, write_versioned_signature},
        alloc::vec::Vec,
        orchard::primitives::redpallas,
        orchard::sighash_kind::{OrchardSig, OrchardSighashKind},
        rand_core::{OsRng, RngCore},
        std::io::Cursor,
    };

    #[test]
    fn write_read_versioned_signature_roundtrip() {
        let mut sig_bytes = [0u8; 64];
        OsRng.fill_bytes(&mut sig_bytes);
        let sig = redpallas::Signature::<redpallas::SpendAuth>::from(sig_bytes);
        let versioned_sig = OrchardSig::new(OrchardSighashKind::AllEffecting, sig);

        // Write the versioned signature to a buffer
        let mut buf = Vec::new();
        write_versioned_signature(&mut buf, &versioned_sig).unwrap();

        // Read the versioned signature back from the buffer
        let mut reader = Cursor::new(buf);
        let read_versioned_sig =
            read_versioned_signature::<_, redpallas::SpendAuth>(&mut reader).unwrap();

        assert_eq!(versioned_sig, read_versioned_sig);
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use orchard::bundle::{
        Authorized, Bundle, BundleVersion, Flags,
        testing::{self as t_orch},
    };
    use zcash_protocol::value::{ZatBalance, testing::arb_zat_balance};

    use crate::transaction::TxVersion;

    prop_compose! {
        pub fn arb_bundle(n_actions: usize)(
            orchard_value_balance in arb_zat_balance(),
            // Never draws the ZSA version: `rebuild_with_version` reinterprets the bundle under a
            // vanilla version, which rejects ZSA-sized note ciphertexts.
            bundle in t_orch::arb_bundle_vanilla(n_actions)
        ) -> Bundle<Authorized, ZatBalance> {
            // overwrite the value balance, as we can't guarantee that the
            // value doesn't exceed the MAX_MONEY bounds.
            bundle.try_map_value_balance::<_, (), _>(|_| Ok(orchard_value_balance)).unwrap()
        }
    }

    #[cfg(zcash_unstable = "nu7")]
    prop_compose! {
        pub fn arb_zsa_bundle(n_actions: usize)(
            orchard_value_balance in arb_zat_balance(),
            bundle in t_orch::arb_bundle_zsa(n_actions)
        ) -> Bundle<Authorized, ZatBalance> {
            // overwrite the value balance, as we can't guarantee that the
            // value doesn't exceed the MAX_MONEY bounds.
            bundle.try_map_value_balance::<_, (), _>(|_| Ok(orchard_value_balance)).unwrap()
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<Bundle<Authorized, ZatBalance>>> {
        if v.has_orchard() {
            // The Orchard slot uses `orchard_v3()` from a v6 transaction onward (cross-address
            // forbidden) and `orchard_v2()` in a v5 transaction; the Ironwood slot is generated
            // separately by `arb_ironwood_bundle_for_version`.
            let bundle_version = orchard_bundle_version(v);
            (1usize..100)
                .prop_flat_map(move |n| {
                    prop::option::of(
                        arb_bundle(n).prop_map(move |b| rebuild_with_version(b, bundle_version)),
                    )
                })
                .boxed()
        } else {
            Just(None).boxed()
        }
    }

    /// Generates Ironwood bundles for the v6 and v7 transaction formats. Unlike the Orchard v6
    /// pool, the Ironwood pool permits cross-address transfers, so this exercises the Ironwood
    /// serialization path the Orchard generator cannot. The v7 Ironwood slot always carries the
    /// ZSA bundle ([`BundleVersion::zsa`]).
    pub fn arb_ironwood_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<Bundle<Authorized, ZatBalance>>> {
        #[cfg(zcash_unstable = "nu7")]
        if v.has_orchard_zsa() {
            return (1usize..100)
                .prop_flat_map(|n| prop::option::of(arb_zsa_bundle(n)))
                .boxed();
        }

        if v.has_ironwood() {
            (1usize..100)
                .prop_flat_map(|n| {
                    prop::option::of(
                        arb_bundle(n)
                            .prop_map(|b| rebuild_with_version(b, BundleVersion::ironwood_v3())),
                    )
                })
                .boxed()
        } else {
            Just(None).boxed()
        }
    }

    /// The Orchard-slot [`BundleVersion`] for a transaction version: `orchard_v3()` from v6 onward
    /// (where the Orchard pool forbids cross-address transfers), `orchard_v2()` otherwise. The
    /// Ironwood pool exists exactly from that point, so `has_ironwood` identifies it.
    fn orchard_bundle_version(v: TxVersion) -> BundleVersion {
        if v.has_ironwood() {
            BundleVersion::orchard_v3()
        } else {
            BundleVersion::orchard_v2()
        }
    }

    /// Rebuilds an arbitrary bundle under `bundle_version`, choosing a cross-address flag value
    /// that the version can represent while preserving the generated spend/output flags.
    ///
    /// Cross-address is only encodable in bit 2 for the Ironwood pool, so bit 2 is set there (to
    /// exercise that serialization path) and left clear otherwise: pre-NU6.3 Orchard has
    /// cross-address implicitly enabled, and post-NU6.3 Orchard forbids it.
    pub(crate) fn rebuild_with_version(
        bundle: Bundle<Authorized, ZatBalance>,
        bundle_version: BundleVersion,
    ) -> Bundle<Authorized, ZatBalance> {
        let mut byte = u8::from(bundle.flags().spends_enabled())
            | (u8::from(bundle.flags().outputs_enabled()) << 1);
        if bundle_version == BundleVersion::ironwood_v3() {
            byte |= 0b100;
        }
        let flags = Flags::from_byte(byte, bundle_version)
            .expect("constructed flag byte is representable under the target version");
        ::orchard::Bundle::try_from_parts(
            bundle.actions().clone(),
            flags,
            *bundle.value_balance(),
            bundle.burn().clone(),
            *bundle.anchor(),
            bundle.authorization().clone(),
            bundle_version,
        )
        .expect("flags are representable under the target version")
    }
}
