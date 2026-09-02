//! Strict snarkjs `.wtns` reader.
//!
//! The prover accepts untrusted artifact bytes at its WASM boundary, so malformed
//! headers, section lengths, non-canonical field elements, and truncated data are
//! rejected instead of being reduced into the field or triggering a panic.

use std::io::{Cursor, Read, Seek, SeekFrom};

use ark_bn254::Fr;
use ark_ff::{BigInteger256, PrimeField};
use byteorder::{LittleEndian, ReadBytesExt};
use thiserror::Error;

const WTNS_VERSION: u32 = 2;
const BN254_FIELD_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum WtnsError {
    #[error("failed to read witness data: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid witness magic")]
    InvalidMagic,
    #[error("unsupported witness version {0}")]
    UnsupportedVersion(u32),
    #[error("witness header section is missing or invalid")]
    InvalidHeader,
    #[error("witness data section is missing")]
    MissingData,
    #[error("witness section {0} appears more than once")]
    DuplicateSection(u32),
    #[error("witness section exceeds the artifact length")]
    SectionOutOfBounds,
    #[error("witness field modulus does not match BN254")]
    WrongField,
    #[error("witness element {0} is not a canonical BN254 scalar")]
    NonCanonicalField(usize),
}

/// Decode a complete snarkjs witness assignment, including the leading constant
/// signal at index zero.
pub fn read_wtns(bytes: &[u8]) -> Result<Vec<Fr>, WtnsError> {
    let mut reader = Cursor::new(bytes);
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != b"wtns" {
        return Err(WtnsError::InvalidMagic);
    }

    let version = reader.read_u32::<LittleEndian>()?;
    if version != WTNS_VERSION {
        return Err(WtnsError::UnsupportedVersion(version));
    }
    let section_count = reader.read_u32::<LittleEndian>()?;

    let mut field_bytes = None;
    let mut witness_count = None;
    let mut data_section = None;

    for _ in 0..section_count {
        let section_id = reader.read_u32::<LittleEndian>()?;
        let section_size = reader.read_u64::<LittleEndian>()?;
        let section_start = reader.stream_position()?;
        let section_end = section_start
            .checked_add(section_size)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or(WtnsError::SectionOutOfBounds)?;

        match section_id {
            1 => {
                if field_bytes.is_some() {
                    return Err(WtnsError::DuplicateSection(section_id));
                }
                let n8 = reader.read_u32::<LittleEndian>()? as usize;
                if n8 != BN254_FIELD_BYTES {
                    return Err(WtnsError::WrongField);
                }
                let expected_header_size = 8_u64
                    .checked_add(n8 as u64)
                    .ok_or(WtnsError::InvalidHeader)?;
                if section_size != expected_header_size {
                    return Err(WtnsError::InvalidHeader);
                }
                let modulus = read_big_integer(&mut reader)?;
                if modulus != Fr::MODULUS {
                    return Err(WtnsError::WrongField);
                }
                let count = reader.read_u32::<LittleEndian>()? as usize;
                if count == 0 {
                    return Err(WtnsError::InvalidHeader);
                }
                field_bytes = Some(n8);
                witness_count = Some(count);
            }
            2 => {
                if data_section
                    .replace((section_start, section_size))
                    .is_some()
                {
                    return Err(WtnsError::DuplicateSection(section_id));
                }
            }
            _ => {}
        }
        reader.seek(SeekFrom::Start(section_end))?;
    }

    let n8 = field_bytes.ok_or(WtnsError::InvalidHeader)?;
    let count = witness_count.ok_or(WtnsError::InvalidHeader)?;
    let (data_start, data_size) = data_section.ok_or(WtnsError::MissingData)?;
    let expected_size = count.checked_mul(n8).ok_or(WtnsError::SectionOutOfBounds)? as u64;
    if data_size != expected_size {
        return Err(WtnsError::SectionOutOfBounds);
    }

    reader.seek(SeekFrom::Start(data_start))?;
    let mut assignment = Vec::with_capacity(count);
    for index in 0..count {
        let value = read_big_integer(&mut reader)?;
        assignment.push(Fr::from_bigint(value).ok_or(WtnsError::NonCanonicalField(index))?);
    }
    Ok(assignment)
}

fn read_big_integer<R: Read>(reader: &mut R) -> Result<BigInteger256, std::io::Error> {
    Ok(BigInteger256::new([
        reader.read_u64::<LittleEndian>()?,
        reader.read_u64::<LittleEndian>()?,
        reader.read_u64::<LittleEndian>()?,
        reader.read_u64::<LittleEndian>()?,
    ]))
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};

    use super::{WtnsError, read_wtns};

    #[test]
    fn rejects_non_witness_data() {
        assert!(matches!(
            read_wtns(b"not a witness"),
            Err(WtnsError::InvalidMagic)
        ));
    }

    #[test]
    fn rejects_non_canonical_field_elements() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"wtns");
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&40_u64.to_le_bytes());
        bytes.extend_from_slice(&32_u32.to_le_bytes());
        bytes.extend_from_slice(&Fr::MODULUS.to_bytes_le());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&32_u64.to_le_bytes());
        bytes.extend_from_slice(&Fr::MODULUS.to_bytes_le());

        assert!(matches!(
            read_wtns(&bytes),
            Err(WtnsError::NonCanonicalField(0))
        ));
    }
}
