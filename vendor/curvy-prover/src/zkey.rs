// Migrated from ark-circom 0.6.0 (https://github.com/arkworks-rs/circom-compat),
// licensed MIT OR Apache-2.0. Local changes: the wasmer-based witness calculator
// is removed, point deserialization is unchecked with a verifying-key anchor
// spot-check (see `read_zkey`), and the bulk point sections convert in parallel
// under the `parallel` feature.
//! ZKey Parsing
//!
//! Each ZKey file is broken into sections:
//!  Header(1)
//!       Prover Type 1 Groth
//!  HeaderGroth(2)
//!       n8q
//!       q
//!       n8r
//!       r
//!       NVars
//!       NPub
//!       DomainSize  (multiple of 2
//!       alpha1
//!       beta1
//!       delta1
//!       beta2
//!       gamma2
//!       delta2
//!  IC(3)
//!  Coefs(4)
//!  PointsA(5)
//!  PointsB1(6)
//!  PointsB2(7)
//!  PointsC(8)
//!  PointsH(9)
//!  Contributions(10)
use ark_ff::{BigInteger256, PrimeField, Zero};
use ark_relations::utils::matrix::Matrix;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use ark_std::log2;
use byteorder::{LittleEndian, ReadBytesExt};

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_groth16::{ProvingKey, VerifyingKey};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

type IoResult<T> = Result<T, SerializationError>;

/// The Circom matrices and metadata parsed from a snarkjs zkey.
///
/// Arkworks 0.6 accepts the three matrices directly during proof generation;
/// this container retains the metadata needed for assignment validation.
pub struct ZkeyMatrices<F> {
    pub(crate) num_instance_variables: usize,
    pub(crate) num_constraints: usize,
    pub(crate) matrices: [Matrix<F>; 3],
}

#[derive(Clone, Debug)]
struct Section {
    position: u64,
    size: usize,
}

/// Reads a SnarkJS ZKey file into an Arkworks ProvingKey.
pub fn read_zkey<R: Read + Seek>(
    reader: &mut R,
) -> IoResult<(ProvingKey<Bn254>, ZkeyMatrices<Fr>)> {
    let mut binfile = BinFile::new(reader)?;
    let proving_key = binfile.proving_key()?;
    let matrices = binfile.matrices()?;
    spot_check(&proving_key)?;
    Ok((proving_key, matrices))
}

// Cheap sanity net for the unchecked bulk deserialization: validate the vk
// anchor points plus the first/last element of every query vector. Catches
// endianness/offset misparses and gross corruption at ~a dozen curve checks;
// full artifact integrity is the caller's job (content-hash the .zkey once).
fn spot_check(pk: &ProvingKey<Bn254>) -> IoResult<()> {
    use ark_ec::AffineRepr;
    fn ok_g1(p: &G1Affine) -> bool {
        p.is_zero() || (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve())
    }
    fn ok_g2(p: &G2Affine) -> bool {
        p.is_zero() || (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve())
    }
    let ends_g1 = |v: &Vec<G1Affine>| {
        v.first().map(ok_g1).unwrap_or(true) && v.last().map(ok_g1).unwrap_or(true)
    };
    let valid = ok_g1(&pk.vk.alpha_g1)
        && ok_g1(&pk.beta_g1)
        && ok_g2(&pk.vk.beta_g2)
        && ok_g2(&pk.vk.gamma_g2)
        && ok_g1(&pk.delta_g1)
        && ok_g2(&pk.vk.delta_g2)
        && ends_g1(&pk.vk.gamma_abc_g1)
        && ends_g1(&pk.a_query)
        && ends_g1(&pk.b_g1_query)
        && ends_g1(&pk.l_query)
        && ends_g1(&pk.h_query)
        && pk.b_g2_query.first().map(ok_g2).unwrap_or(true)
        && pk.b_g2_query.last().map(ok_g2).unwrap_or(true);
    if !valid {
        return Err(SerializationError::InvalidData);
    }
    Ok(())
}

#[derive(Debug)]
struct BinFile<'a, R> {
    #[allow(dead_code)]
    ftype: String,
    #[allow(dead_code)]
    version: u32,
    sections: HashMap<u32, Vec<Section>>,
    reader: &'a mut R,
}

impl<'a, R: Read + Seek> BinFile<'a, R> {
    fn new(reader: &'a mut R) -> IoResult<Self> {
        let file_length = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"zkey" {
            return Err(SerializationError::InvalidData);
        }

        let version = reader.read_u32::<LittleEndian>()?;
        if version != 1 {
            return Err(SerializationError::InvalidData);
        }

        let num_sections = reader.read_u32::<LittleEndian>()?;

        let mut sections = HashMap::new();
        for _ in 0..num_sections {
            let section_id = reader.read_u32::<LittleEndian>()?;
            let section_length = reader.read_u64::<LittleEndian>()?;
            let section_position = reader.stream_position()?;
            let section_end = section_position
                .checked_add(section_length)
                .filter(|end| *end <= file_length)
                .ok_or(SerializationError::InvalidData)?;
            let section_size =
                usize::try_from(section_length).map_err(|_| SerializationError::InvalidData)?;

            let section = sections.entry(section_id).or_insert_with(Vec::new);
            section.push(Section {
                position: section_position,
                size: section_size,
            });

            reader.seek(SeekFrom::Start(section_end))?;
        }

        Ok(Self {
            ftype: "zkey".to_string(),
            version,
            sections,
            reader,
        })
    }

    fn proving_key(&mut self) -> IoResult<ProvingKey<Bn254>> {
        let header = self.groth_header()?;
        let l_query_size = header
            .n_vars
            .checked_sub(header.n_public + 1)
            .ok_or(SerializationError::InvalidData)?;
        let ic = self.ic(header.n_public)?;

        let a_query = self.a_query(header.n_vars)?;
        let b_g1_query = self.b_g1_query(header.n_vars)?;
        let b_g2_query = self.b_g2_query(header.n_vars)?;
        let l_query = self.l_query(l_query_size)?;
        let h_query = self.h_query(header.domain_size as usize)?;

        let vk = VerifyingKey::<Bn254> {
            alpha_g1: header.verifying_key.alpha_g1,
            beta_g2: header.verifying_key.beta_g2,
            gamma_g2: header.verifying_key.gamma_g2,
            delta_g2: header.verifying_key.delta_g2,
            gamma_abc_g1: ic,
        };

        let pk = ProvingKey::<Bn254> {
            vk,
            beta_g1: header.verifying_key.beta_g1,
            delta_g1: header.verifying_key.delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        };

        Ok(pk)
    }

    fn get_section(&self, id: u32) -> IoResult<Section> {
        let sections = self
            .sections
            .get(&id)
            .ok_or(SerializationError::InvalidData)?;
        if sections.len() != 1 {
            return Err(SerializationError::InvalidData);
        }
        sections
            .first()
            .cloned()
            .ok_or(SerializationError::InvalidData)
    }

    fn groth_header(&mut self) -> IoResult<HeaderGroth> {
        let section = self.get_section(2)?;
        let header = HeaderGroth::new(&mut self.reader, &section)?;
        Ok(header)
    }

    fn ic(&mut self, n_public: usize) -> IoResult<Vec<G1Affine>> {
        // the range is non-inclusive so we do +1 to get all inputs
        self.g1_section(n_public + 1, 3)
    }

    /// Returns the constraint matrices and metadata corresponding to the zkey.
    pub fn matrices(&mut self) -> IoResult<ZkeyMatrices<Fr>> {
        let header = self.groth_header()?;

        let section = self.get_section(4)?;
        self.reader.seek(SeekFrom::Start(section.position))?;
        let num_coeffs: u32 = self.reader.read_u32::<LittleEndian>()?;

        // insantiate AB
        let mut matrices = vec![vec![vec![]; header.domain_size as usize]; 2];
        let mut max_constraint_index = None;
        for _ in 0..num_coeffs {
            let matrix: u32 = self.reader.read_u32::<LittleEndian>()?;
            let constraint: u32 = self.reader.read_u32::<LittleEndian>()?;
            let signal: u32 = self.reader.read_u32::<LittleEndian>()?;
            if matrix > 1 || constraint >= header.domain_size || signal as usize >= header.n_vars {
                return Err(SerializationError::InvalidData);
            }

            let value: Fr = deserialize_field_fr(&mut self.reader)?;
            max_constraint_index = Some(
                max_constraint_index
                    .map_or(constraint, |current| std::cmp::max(current, constraint)),
            );
            matrices[matrix as usize][constraint as usize].push((value, signal as usize));
        }

        let num_constraints = max_constraint_index
            .ok_or(SerializationError::InvalidData)?
            .checked_sub(header.n_public as u32)
            .ok_or(SerializationError::InvalidData)? as usize;
        // Remove the public input constraints, Arkworks adds them later
        matrices.iter_mut().for_each(|m| {
            m.truncate(num_constraints);
        });
        // Move the two rows out instead of cloning them: cloning held a second full
        // copy of every retained coefficient while the source was still live.
        // `shrink_to_fit` then releases the push-growth slack one linear combination
        // at a time, so compaction never doubles the whole matrix either.
        //
        // Measured peak RSS for `Prover::from_zkey_bytes`, macOS release build:
        //   pending(50,30), 882 MiB zkey - 3076.05 -> 2802.61 MiB, load 882 -> 808 ms
        //   pending(5,30),  123 MiB zkey -  430.69 ->  392.81 MiB, load 128 -> 114 ms
        // Load gets faster because 6.46M coefficient entries are no longer copied.
        let mut rows = matrices.into_iter();
        let mut a = rows.next().ok_or(SerializationError::InvalidData)?;
        let mut b = rows.next().ok_or(SerializationError::InvalidData)?;
        for combination in a.iter_mut().chain(b.iter_mut()) {
            combination.shrink_to_fit();
        }

        Ok(ZkeyMatrices {
            num_instance_variables: header.n_public + 1,
            num_constraints,
            matrices: [a, b, vec![]],
        })
    }

    fn a_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 5)
    }

    fn b_g1_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 6)
    }

    fn b_g2_query(&mut self, n_vars: usize) -> IoResult<Vec<G2Affine>> {
        self.g2_section(n_vars, 7)
    }

    fn l_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 8)
    }

    fn h_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 9)
    }

    fn g1_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G1Affine>> {
        let section = self.get_section(section_id as u32)?;
        let expected_size = num
            .checked_mul(G1_BYTES)
            .ok_or(SerializationError::InvalidData)?;
        if section.size != expected_size {
            return Err(SerializationError::InvalidData);
        }
        self.reader.seek(SeekFrom::Start(section.position))?;
        deserialize_g1_vec(self.reader, num)
    }

    fn g2_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G2Affine>> {
        let section = self.get_section(section_id as u32)?;
        let expected_size = num
            .checked_mul(G2_BYTES)
            .ok_or(SerializationError::InvalidData)?;
        if section.size != expected_size {
            return Err(SerializationError::InvalidData);
        }
        self.reader.seek(SeekFrom::Start(section.position))?;
        deserialize_g2_vec(self.reader, num)
    }
}

#[derive(Default, Clone, Debug, CanonicalDeserialize)]
pub struct ZVerifyingKey {
    alpha_g1: G1Affine,
    beta_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g1: G1Affine,
    delta_g2: G2Affine,
}

impl ZVerifyingKey {
    fn new<R: Read>(reader: &mut R) -> IoResult<Self> {
        let alpha_g1 = deserialize_g1(reader)?;
        let beta_g1 = deserialize_g1(reader)?;
        let beta_g2 = deserialize_g2(reader)?;
        let gamma_g2 = deserialize_g2(reader)?;
        let delta_g1 = deserialize_g1(reader)?;
        let delta_g2 = deserialize_g2(reader)?;

        Ok(Self {
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
        })
    }
}

#[derive(Clone, Debug)]
struct HeaderGroth {
    #[allow(dead_code)]
    n8q: u32,
    #[allow(dead_code)]
    q: BigInteger256,
    #[allow(dead_code)]
    n8r: u32,
    #[allow(dead_code)]
    r: BigInteger256,

    n_vars: usize,
    n_public: usize,

    domain_size: u32,
    #[allow(dead_code)]
    power: u32,

    verifying_key: ZVerifyingKey,
}

impl HeaderGroth {
    fn new<R: Read + Seek>(reader: &mut R, section: &Section) -> IoResult<Self> {
        reader.seek(SeekFrom::Start(section.position))?;
        Self::read(reader)
    }

    fn read<R: Read>(mut reader: &mut R) -> IoResult<Self> {
        let n8q: u32 = u32::deserialize_uncompressed(&mut reader)?;
        // group order r of Bn254
        let q = BigInteger256::deserialize_uncompressed(&mut reader)?;

        let n8r: u32 = u32::deserialize_uncompressed(&mut reader)?;
        // Prime field modulus
        let r = BigInteger256::deserialize_uncompressed(&mut reader)?;

        let n_vars = u32::deserialize_uncompressed(&mut reader)? as usize;
        let n_public = u32::deserialize_uncompressed(&mut reader)? as usize;

        let domain_size: u32 = u32::deserialize_uncompressed(&mut reader)?;
        if n8q != 32
            || q != Fq::MODULUS
            || n8r != 32
            || r != Fr::MODULUS
            || n_vars <= n_public
            || domain_size == 0
            || !domain_size.is_power_of_two()
        {
            return Err(SerializationError::InvalidData);
        }
        let power = log2(domain_size as usize);

        let verifying_key = ZVerifyingKey::new(&mut reader)?;

        Ok(Self {
            n8q,
            q,
            n8r,
            r,
            n_vars,
            n_public,
            domain_size,
            power,
            verifying_key,
        })
    }
}

// need to divide by R, since snarkjs outputs the zkey with coefficients
// multiplieid by R^2
fn deserialize_field_fr<R: Read>(reader: &mut R) -> IoResult<Fr> {
    let bigint = BigInteger256::deserialize_uncompressed(reader)?;
    Ok(Fr::new_unchecked(Fr::new_unchecked(bigint).into_bigint()))
}

// skips the multiplication by R because Circom points are already in Montgomery form
fn deserialize_field<R: Read>(reader: &mut R) -> IoResult<Fq> {
    let bigint = BigInteger256::deserialize_uncompressed(reader)?;
    // if you use Fq::new it multiplies by R
    Ok(Fq::new_unchecked(bigint))
}

pub fn deserialize_field2<R: Read>(reader: &mut R) -> IoResult<Fq2> {
    let c0 = deserialize_field(reader)?;
    let c1 = deserialize_field(reader)?;
    Ok(Fq2::new(c0, c1))
}

// UNCHECKED point construction (vendored change vs ark-circom): upstream used
// `Affine::new`, which runs an on-curve check per point and a subgroup check
// per G2 point - for a 226k-constraint zkey that is ~1M G1 + ~230k G2 curve
// checks on EVERY load of a static, hash-pinnable artifact, and it dominated
// cold start (23 s in wasm). Integrity belongs on the ARTIFACT (content hash /
// one-time validation), not per point per load; `read_zkey` still spot-checks
// the vk anchor points, which catches gross corruption/misparse for free.
fn deserialize_g1<R: Read>(reader: &mut R) -> IoResult<G1Affine> {
    let x = deserialize_field(reader)?;
    let y = deserialize_field(reader)?;
    let infinity = x.is_zero() && y.is_zero();
    if infinity {
        Ok(G1Affine::identity())
    } else {
        Ok(G1Affine::new_unchecked(x, y))
    }
}

fn deserialize_g2<R: Read>(reader: &mut R) -> IoResult<G2Affine> {
    let f1 = deserialize_field2(reader)?;
    let f2 = deserialize_field2(reader)?;
    let infinity = f1.is_zero() && f2.is_zero();
    if infinity {
        Ok(G2Affine::identity())
    } else {
        Ok(G2Affine::new_unchecked(f1, f2))
    }
}

const G1_BYTES: usize = 64; // two 32-byte Montgomery-form Fq limbs
const G2_BYTES: usize = 128; // two Fq2

// Bulk point sections: read the raw bytes in one go, then convert - in parallel
// chunks under the `parallel` feature (the conversion is pure per-point work).
fn deserialize_g1_vec<R: Read>(reader: &mut R, n_vars: usize) -> IoResult<Vec<G1Affine>> {
    let byte_count = n_vars
        .checked_mul(G1_BYTES)
        .ok_or(SerializationError::InvalidData)?;
    let mut bytes = vec![0u8; byte_count];
    reader.read_exact(&mut bytes)?;
    let convert = |chunk: &[u8]| deserialize_g1(&mut &chunk[..]);
    #[cfg(feature = "parallel")]
    return bytes.par_chunks_exact(G1_BYTES).map(convert).collect();
    #[cfg(not(feature = "parallel"))]
    bytes.chunks_exact(G1_BYTES).map(convert).collect()
}

fn deserialize_g2_vec<R: Read>(reader: &mut R, n_vars: usize) -> IoResult<Vec<G2Affine>> {
    let byte_count = n_vars
        .checked_mul(G2_BYTES)
        .ok_or(SerializationError::InvalidData)?;
    let mut bytes = vec![0u8; byte_count];
    reader.read_exact(&mut bytes)?;
    let convert = |chunk: &[u8]| deserialize_g2(&mut &chunk[..]);
    #[cfg(feature = "parallel")]
    return bytes.par_chunks_exact(G2_BYTES).map(convert).collect();
    #[cfg(not(feature = "parallel"))]
    bytes.chunks_exact(G2_BYTES).map(convert).collect()
}
