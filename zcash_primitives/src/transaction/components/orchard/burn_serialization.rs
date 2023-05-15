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

fn write_asset_burn<W: Write>(
    mut writer: W,
    (asset_base, amount): &(AssetBase, Amount),
) -> io::Result<()> {
    write_asset_base(&mut writer, asset_base)?;
    write_amount(&mut writer, amount)?;

    Ok(())
}

pub fn write_bundle_burn<W: Write>(
    mut writer: W,
    bundle_burn: &Vec<(AssetBase, Amount)>,
) -> io::Result<()> {
    Vector::write(&mut writer, bundle_burn, |w, b| write_asset_burn(w, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use crate::transaction::tests::create_test_asset;

    use super::super::burn_validation::BurnError;

    #[test]
    fn test_read_write_bundle_burn_success() {
        let bundle_burn = (1..10)
            .map(|i| {
                (
                    create_test_asset(&format!("Asset {i}")),
                    Amount::from_u64(i * 10).unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);
        write_bundle_burn(&mut cursor, &bundle_burn).unwrap();

        cursor.set_position(0);
        let result = read_bundle_burn(&mut cursor).unwrap();

        assert_eq!(result, bundle_burn);
    }

    // This test implementation covers only one failure case intentionally,
    // as the other cases are already covered in the validate_bundle_burn tests.
    #[test]
    fn test_read_bundle_burn_duplicate_asset() {
        let bundle_burn = vec![
            (create_test_asset("Asset 1"), Amount::from_u64(10).unwrap()),
            (create_test_asset("Asset 1"), Amount::from_u64(20).unwrap()),
            (create_test_asset("Asset 3"), Amount::from_u64(10).unwrap()),
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
