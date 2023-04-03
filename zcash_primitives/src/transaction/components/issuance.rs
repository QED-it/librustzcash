/// Functions for parsing & serialization of the issuance bundle components.
use std::io;
use std::io::{Read, Write};
use bitvec::macros::internal::funty::Fundamental;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use nonempty::NonEmpty;
use orchard::issuance::{IssueAction, IssueBundle, Signed};
use orchard::{Address, Note};
use orchard::keys::IssuanceValidatingKey;
use orchard::note::{AssetId, Nullifier, RandomSeed};
use orchard::value::NoteValue;
use zcash_encoding::{Array, CompactSize, Vector};
use crate::transaction::components::orchard::{read_nullifier, read_signature};


/// Reads an [`orchard::Bundle`] from a v5 transaction format.
pub fn read_v5_bundle<R: Read>(
    mut reader: R,
) -> io::Result<Option<IssueBundle<Signed>>> {
    let actions = Vector::read(&mut reader, |r| read_action(r))?;
    if actions.is_empty() {
        Ok(None)
    } else {
        let ik = read_ik(&mut reader);
        let authorization = read_authorization(&mut reader);

        Ok(Some(IssueBundle::from_parts(
            ik?,
            actions,
            authorization?,
        )))
    }
}

fn read_ik<R: Read>(mut reader: R) -> io::Result<IssuanceValidatingKey>  {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(IssuanceValidatingKey::from_bytes(&bytes).unwrap())
}

fn read_authorization<R: Read>(mut reader: R) -> io::Result<Signed>  {
    let signature = read_signature(&mut reader).unwrap();
    Ok(Signed::from_parts(signature))
}


fn read_action<R: Read>(mut reader: R) -> io::Result<IssueAction> {
    let finalize = reader.read_u8()?.as_bool();
    let notes = Vector::read(&mut reader, |r| read_note(r))?;
    let mut asset_descr: String = String::new();
    reader.read_to_string(&mut asset_descr)?;

    Ok(IssueAction::from_parts(
        asset_descr.to_owned(),
        NonEmpty::from_vec(notes).unwrap(),
        finalize
    ))
}

fn read_note<R: Read>(mut reader: R) -> io::Result<Note> {
    let recipient = read_recipient(&mut reader)?;
    let value = reader.read_u64::<LittleEndian>()?;
    let asset = read_asset(&mut reader)?;
    let rho = read_nullifier(&mut reader)?;
    let rseed = read_rseed(&mut reader, &rho)?;
    Ok(Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        asset,
        rho,
        rseed,
    )).unwrap())
}

fn read_recipient<R: Read>(mut reader: R) -> io::Result<Address> {
    let mut bytes = [0u8; 43];
    reader.read_exact(&mut bytes)?;
    Ok(Option::from(Address::from_raw_address_bytes(&bytes)).unwrap())
}

fn read_asset<R: Read>(mut reader: R) -> io::Result<AssetId> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(Option::from(AssetId::native()/*AssetId::from_bytes(&bytes)*/).unwrap())
}

fn read_rseed<R: Read>(mut reader: R, nullifier: &Nullifier) -> io::Result<RandomSeed> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(Option::from(RandomSeed::from_bytes(bytes, nullifier)).unwrap())
}

/// Writes an [`orchard::issuance::IssueBundle`] in the v5 transaction format.
pub fn write_v5_bundle<W: Write>(
    bundle: Option<&IssueBundle<Signed>>,
    mut writer: W,
) -> io::Result<()> {
    if let Some(bundle) = &bundle {
        Array::write(
            &mut writer,
            bundle.actions(),
            |w, action| write_issue_action(action, w),
        )?;
        writer.write_all(&bundle.ik().to_bytes())?;
        writer.write_all(&<[u8; 64]>::from(
            bundle.authorization().signature(),
        ))?;

    } else {
        CompactSize::write(&mut writer, 0)?;
    }
    Ok(())
}

fn write_issue_action<W: Write>(action: &IssueAction, mut writer: W) -> io::Result<()> {
    writer.write_u8(action.is_finalized().as_u8())?;

    Vector::write_nonempty(&mut writer, action.notes(), |w, note| {
        write_note(note, w)
    })?;

    writer.write_all(action.asset_desc().as_bytes())?;
    Ok(())
}

fn write_note<W: Write>(note: &Note, writer: &mut W) -> io::Result<()> {
    writer.write_all(&note.recipient().to_raw_address_bytes())?;
    writer.write_u64::<LittleEndian>(note.value().inner())?;
    writer.write_all(&note.asset().to_bytes())?;
    writer.write_all(&note.rho().to_bytes())?;
    writer.write_all(note.rseed().as_bytes())?;
    Ok(())
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use orchard::issuance::{IssueBundle, Signed, testing::{self as t_issue}};

    use crate::transaction::{
        TxVersion,
    };

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
        if v.has_orchard() {
            Strategy::boxed((1usize..100).prop_flat_map(|n| prop::option::of(arb_issue_bundle(n))))
        } else {
            Strategy::boxed(Just(None))
        }
    }
}