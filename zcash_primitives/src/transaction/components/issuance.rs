use std::collections::HashMap;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use nonempty::NonEmpty;
use orchard::issuance::{IssueAction, IssueAuth, IssueBundle, Signed};
use orchard::keys::IssuanceValidatingKey;
use orchard::note::{AssetBase, RandomSeed, Rho};
use orchard::value::NoteValue;
use orchard::{Address, Note};
/// Functions for parsing & serialization of the issuance bundle components.
use std::io;
use std::io::{Error, ErrorKind, Read, Write};
use zcash_encoding::{CompactSize, Vector};

/// Reads an [`orchard::Bundle`] from a v6 transaction format.
pub fn read_v6_bundle<R: Read>(mut reader: R) -> io::Result<Option<IssueBundle<Signed>>> {
    let actions = Vector::read(&mut reader, |r| read_action(r))?;

    if actions.is_empty() {
        Ok(None)
    } else {
        let ik = read_ik(&mut reader)?;
        let authorization = read_authorization(&mut reader)?;
        let reference_notes = read_reference_notes(&mut reader)?;

        Ok(Some(IssueBundle::from_parts(
            ik,
            NonEmpty::from_vec(actions).unwrap(),
            reference_notes,
            authorization,
        )))
    }
}

fn read_reference_notes<R: Read>(mut _reader: R) -> io::Result<HashMap<AssetBase, Note>> {
    // TODO
    Ok(HashMap::new())
}

fn read_ik<R: Read>(mut reader: R) -> io::Result<IssuanceValidatingKey> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    IssuanceValidatingKey::from_bytes(&bytes).ok_or(Error::new(
        ErrorKind::InvalidData,
        "Invalid Pallas point for IssuanceValidatingKey",
    ))
}

fn read_authorization<R: Read>(mut reader: R) -> io::Result<Signed> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "Invalid signature for IssuanceAuthorization",
        )
    })?;
    Ok(Signed::from_data(bytes))
}

fn read_action<R: Read>(mut reader: R) -> io::Result<IssueAction> {
    let asset_descr_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    let notes = Vector::read(&mut reader, |r| read_note(r))?;
    let finalize = match reader.read_u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid value for finalize",
            ))
        }
    };
    Ok(IssueAction::from_parts(asset_descr_bytes, notes, finalize))
}

pub fn read_note<R: Read>(mut reader: R) -> io::Result<Note> {
    let recipient = read_recipient(&mut reader)?;
    let value = reader.read_u64::<LittleEndian>()?;
    let asset = read_asset(&mut reader)?;
    let rho = read_rho(&mut reader)?;
    let rseed = read_rseed(&mut reader, &rho)?;
    Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        asset,
        rho,
        rseed,
    ))
    .ok_or(Error::new(ErrorKind::InvalidData, "Invalid note"))
}

fn read_rho<R: Read>(mut reader: R) -> io::Result<Rho> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(Rho::from_bytes(&bytes)).ok_or(Error::new(
        ErrorKind::InvalidData,
        "invalid Pallas point for rho",
    ))
}

fn read_recipient<R: Read>(mut reader: R) -> io::Result<Address> {
    let mut bytes = [0u8; 43];
    reader.read_exact(&mut bytes)?;
    Option::from(Address::from_raw_address_bytes(&bytes)).ok_or(Error::new(
        ErrorKind::InvalidData,
        "Invalid recipient address",
    ))
}

pub fn read_asset<R: Read>(reader: &mut R) -> io::Result<AssetBase> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(AssetBase::from_bytes(&bytes))
        .ok_or(Error::new(ErrorKind::InvalidData, "Invalid asset"))
}

fn read_rseed<R: Read>(mut reader: R, nullifier: &Rho) -> io::Result<RandomSeed> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(RandomSeed::from_bytes(bytes, nullifier))
        .ok_or(Error::new(ErrorKind::InvalidData, "Invalid rseed"))
}

/// Writes an [`IssueBundle`] in the v6 transaction format.
pub fn write_v6_bundle<W: Write>(
    bundle: Option<&IssueBundle<Signed>>,
    mut writer: W,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        Vector::write_nonempty(&mut writer, bundle.actions(), write_action)?;
        writer.write_all(&bundle.ik().to_bytes())?;
        writer.write_all(&<[u8; 64]>::from(bundle.authorization().signature()))?;
        write_reference_notes(&mut writer, bundle.reference_notes())?;
    } else {
        CompactSize::write(&mut writer, 0)?;
    }
    Ok(())
}

fn write_reference_notes<W: Write>(mut _writer: &mut W, _notes: &HashMap<AssetBase, Note>) -> io::Result<()> {
    // TODO
    Ok(())
}

fn write_action<W: Write>(mut writer: &mut W, action: &IssueAction) -> io::Result<()> {
    Vector::write(&mut writer, action.asset_desc(), |w, b| w.write_u8(*b))?;
    Vector::write(&mut writer, action.notes(), write_note)?;
    writer.write_u8(action.is_finalized() as u8)?;
    Ok(())
}

pub fn write_note<W: Write>(writer: &mut W, note: &Note) -> io::Result<()> {
    writer.write_all(&note.recipient().to_raw_address_bytes())?;
    writer.write_u64::<LittleEndian>(note.value().inner())?;
    writer.write_all(&note.asset().to_bytes())?;
    writer.write_all(&note.rho().to_bytes())?;
    writer.write_all(note.rseed().as_bytes())?;
    Ok(())
}

pub trait MapIssueAuth<A: IssueAuth, B: IssueAuth> {
    fn map_issue_authorization(&self, a: A) -> B;
}

/// The identity map.
///
/// This can be used with [`TransactionData::map_authorization`] when you want to map the
/// authorization of a subset of the transaction's bundles.
///
/// [`TransactionData::map_authorization`]: crate::transaction::TransactionData::map_authorization
impl MapIssueAuth<Signed, Signed> for () {
    fn map_issue_authorization(&self, a: Signed) -> Signed {
        a
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use orchard::issuance::{
        testing::{self as t_issue},
        IssueBundle, Signed,
    };

    use crate::transaction::TxVersion;

    prop_compose! {
        pub fn arb_issue_bundle(n_actions: usize)(
            bundle in t_issue::arb_signed_issue_bundle(n_actions)
        ) -> IssueBundle<Signed> {
            bundle
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<IssueBundle<Signed>>> {
        if v.has_orchard_zsa() {
            Strategy::boxed((1usize..100).prop_flat_map(|n| prop::option::of(arb_issue_bundle(n))))
        } else {
            Strategy::boxed(Just(None))
        }
    }
}
