use std::io::{self, Read, Write};

use orchard::note::AssetBase;

use zcash_encoding::Vector;

use crate::transaction::Transaction;

use super::{burn_validation::validate_bundle_burn, Amount};

fn read_asset_base<R: Read>(mut reader: R) -> io::Result<AssetBase> {
    let mut bytes = [0u8; 32];

    reader.read_exact(&mut bytes)?;

    Option::from(AssetBase::from_bytes(&bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid AssetBase!"))
}

fn read_asset_burn<R: Read>(mut reader: R) -> io::Result<(AssetBase, Amount)> {
    let asset_base = read_asset_base(&mut reader)?;
    let amount = Transaction::read_amount(&mut reader)?;

    Ok((asset_base, amount))
}

pub fn read_bundle_burn<R: Read>(mut reader: R) -> io::Result<Vec<(AssetBase, Amount)>> {
    let burn = Vector::read(&mut reader, |r| read_asset_burn(r))?;
    validate_bundle_burn(&burn)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    Ok(burn)
}

fn write_amount<W: Write>(mut writer: W, amount: &Amount) -> io::Result<()> {
    writer.write_all(&amount.to_i64_le_bytes())
}

fn write_asset_base<W: Write>(mut writer: W, asset_base: &AssetBase) -> io::Result<()> {
    writer.write_all(&asset_base.to_bytes())
}

pub fn write_asset_burn<W: Write>(
    mut writer: W,
    (asset_base, amount): &(AssetBase, Amount),
) -> io::Result<()> {
    write_asset_base(&mut writer, asset_base)?;
    write_amount(&mut writer, amount)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use crate::transaction::tests::get_burn_tuple;

    use super::super::burn_validation::BurnError;

    fn write_bundle_burn<W: Write>(
        mut writer: W,
        bundle_burn: &[(AssetBase, Amount)],
    ) -> io::Result<()> {
        Vector::write(&mut writer, bundle_burn, |w, b| write_asset_burn(w, b))
    }

    #[test]
    fn read_write_bundle_burn_success() {
        let bundle_burn = (1..10)
            .map(|i| get_burn_tuple(&format!("Asset {i}"), i * 10))
            .collect::<Vec<_>>();

        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);
        write_bundle_burn(&mut cursor, &bundle_burn).unwrap();

        cursor.set_position(0);
        let result = read_bundle_burn(&mut cursor).unwrap();

        assert_eq!(result, bundle_burn);
    }

    #[test]
    fn read_bundle_burn_duplicate_asset() {
        let bundle_burn = vec![
            get_burn_tuple("Asset 1", 10),
            get_burn_tuple("Asset 1", 20),
            get_burn_tuple("Asset 3", 10),
        ];

        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);

        write_bundle_burn(&mut cursor, &bundle_burn).unwrap();

        cursor.set_position(0);

        let result = read_bundle_burn(&mut cursor);

        assert!(
            matches!(result, Err(ref err) if err.kind() == io::ErrorKind::InvalidData &&
              err.to_string() == BurnError::DuplicateAsset.to_string())
        );
    }
}
