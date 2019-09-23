#![feature(test)]

extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate test;

use bellman::Circuit;
use bellman::ConstraintSystem;
use bellman::groth16::*;
use bellman::SynthesisError;
use pairing::bls12_381::Bls12;
use rand::{Rand, thread_rng};
use sapling_crypto::{
    circuit::{
        boolean::{AllocatedBit, Boolean},
        pedersen_hash::{pedersen_hash, Personalization},
    },
    jubjub::{
        JubjubBls12,
        JubjubEngine,
    },
};



#[bench]
pub fn bench_proving_pedersen_hashes_255bits_1(b: &mut test::Bencher) {
    prove_pedersen_hashes(b, 255, 1);
}

#[bench]
pub fn bench_proving_pedersen_hashes_255bits_10(b: &mut test::Bencher) {
    prove_pedersen_hashes(b, 255, 10);
}

#[bench]
pub fn bench_proving_pedersen_hashes_510bits_1(b: &mut test::Bencher) {
    prove_pedersen_hashes(b, 255 * 2, 1);
}

#[bench]
pub fn bench_proving_pedersen_hashes_510bits_10(b: &mut test::Bencher) {
    prove_pedersen_hashes(b, 255 * 2, 10);
}

#[bench]
pub fn bench_proving_pedersen_hashes_510bits_100(b: &mut test::Bencher) {
    prove_pedersen_hashes(b, 255 * 2, 100);
}


fn prove_pedersen_hashes(b: &mut test::Bencher, n_bits: u32, n_hashes: u32) {
    let jubjub_params = &JubjubBls12::new();
    let rng = &mut thread_rng();

    assert!(n_bits % 3 == 0 && n_bits >= 6); // Must be a multiple of 3 bits.
    let n_bits = n_bits - 6; // The personalization takes 6 bits already.

    println!("Creating sample parameters...");
    let circuit = PH {
        params: jubjub_params,
        bits: (0..n_bits).map(|_| bool::rand(rng)).collect(),
        n_hashes,
    };
    let groth_params = generate_random_parameters::<Bls12, _, _>(
        circuit,
        rng,
    ).unwrap();

    println!("Proving...");
    b.iter(|| {
        let circuit = PH {
            params: jubjub_params,
            bits: (0..n_bits).map(|_| bool::rand(rng)).collect(),
            n_hashes,
        };

        let _ = create_random_proof(circuit, &groth_params, rng).unwrap();
    });
}


pub struct PH<'a, E: JubjubEngine> {
    pub params: &'a E::Params,
    pub bits: Vec<bool>,
    pub n_hashes: u32,
}

impl<'a, E: JubjubEngine> Circuit<E> for PH<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        for i in 0..self.n_hashes {
            let mut cs = cs.namespace(|| format!("hash {}", i));

            let mut contents: Vec<Boolean> = vec![];

            for j in 0..self.bits.len() {
                contents.push(
                    Boolean::Is(AllocatedBit::alloc(
                        cs.namespace(|| format!("bit {}", j)),
                        Some(self.bits[j]),
                    )?));
            }

            // Compute the hash of the note contents
            let _ = pedersen_hash(
                cs.namespace(|| "pedersen hash"),
                Personalization::NoteCommitment,
                &contents,
                self.params,
            )?;
        }

        Ok(())
    }
}
