use std::{
    collections::HashMap,
    env::current_dir,
    fs,
    path::{Path, PathBuf},
};

use crate::circom::reader::generate_witness_from_bin;
use circom::circuit::{CircomCircuit, R1CS};
use ff::Field;
use arecibo::{
    provider::{Bn256Engine, GrumpkinEngine}, traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine, Group}, PublicParams, RecursiveSNARK
};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(not(target_family = "wasm"))]
use crate::circom::reader::generate_witness_from_wasm;

#[cfg(target_family = "wasm")]
use crate::circom::wasm::generate_witness_from_wasm;

pub mod circom;

pub type F = <Bn256Engine as Engine>::Scalar;
pub type C1 = CircomCircuit<<Bn256Engine as Engine>::Scalar>;
pub type C2 = TrivialCircuit<<GrumpkinEngine as Engine>::Scalar>;

type E1 = Bn256Engine;
type E2 = GrumpkinEngine;

#[derive(Clone)]
pub enum FileLocation {
    PathBuf(PathBuf),
    URL(String),
}

pub fn create_public_params(r1cs: R1CS<F>) -> PublicParams<E1, E2, C1, C2>
{
    let circuit_primary = CircomCircuit {
        r1cs,
        witness: None,
    };

    let circuit_secondary = TrivialCircuit::default();

    PublicParams::<E1, E2, C1, C2>::setup(
        &circuit_primary,
        &circuit_secondary,
        &*default_ck_hint(),
        &*default_ck_hint(),
    )
}

#[derive(Serialize, Deserialize)]
struct CircomInput {
    step_in: Vec<String>,

    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[cfg(not(target_family = "wasm"))]
fn compute_witness(
    current_public_input: Vec<String>,
    private_input: HashMap<String, Value>,
    witness_generator_file: FileLocation,
    witness_generator_output: &Path,
) -> Vec<<arecibo::provider::Bn256Engine as arecibo::traits::Engine>::Scalar>
{
    let decimal_stringified_input: Vec<String> = current_public_input
        .iter()
        .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
        .collect();

    let input = CircomInput {
        step_in: decimal_stringified_input.clone(),
        extra: private_input.clone(),
    };

    let is_wasm = match &witness_generator_file {
        FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
        FileLocation::URL(_) => true,
    };
    let input_json = serde_json::to_string(&input).unwrap();

    if is_wasm {
        generate_witness_from_wasm::<F>(
            &witness_generator_file,
            &input_json,
            &witness_generator_output,
        )
    } else {
        let witness_generator_file = match &witness_generator_file {
            FileLocation::PathBuf(path) => path,
            FileLocation::URL(_) => panic!("unreachable"),
        };
        generate_witness_from_bin::<F>(
            &witness_generator_file,
            &input_json,
            &witness_generator_output,
        )
    }
}

#[cfg(target_family = "wasm")]
async fn compute_witness<E1, E2>(
    current_public_input: Vec<String>,
    private_input: HashMap<String, Value>,
    witness_generator_file: FileLocation,
) -> Vec<<E1 as Group>::Scalar>
where
    E1: Group<Base = <E2 as Group>::Scalar>,
    E2: Group<Base = <E1 as Group>::Scalar>,
{
    let decimal_stringified_input: Vec<String> = current_public_input
        .iter()
        .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
        .collect();

    let input = CircomInput {
        step_in: decimal_stringified_input.clone(),
        extra: private_input.clone(),
    };

    let is_wasm = match &witness_generator_file {
        FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
        FileLocation::URL(_) => true,
    };
    let input_json = serde_json::to_string(&input).unwrap();

    if is_wasm {
        generate_witness_from_wasm::<F<E1>>(
            &witness_generator_file,
            &input_json,
        )
        .await
    } else {
        let root = current_dir().unwrap(); // compute path only when generating witness from a binary
        let witness_generator_output = root.join("circom_witness.wtns");
        let witness_generator_file = match &witness_generator_file {
            FileLocation::PathBuf(path) => path,
            FileLocation::URL(_) => panic!("unreachable"),
        };
        generate_witness_from_bin::<F<E1>>(
            &witness_generator_file,
            &input_json,
            &witness_generator_output,
        )
    }
}

#[cfg(not(target_family = "wasm"))]
pub fn create_recursive_circuit(
    witness_generator_file: FileLocation,
    r1cs: R1CS<F>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F>,
    pp: &PublicParams<E1, E2, C1, C2>,
) -> Result<RecursiveSNARK<E1, E2, C1, C2>, std::io::Error>
{
    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");

    let iteration_count = private_inputs.len();

    let start_public_input_hex = start_public_input
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();
    let mut current_public_input = start_public_input_hex.clone();

    let witness_0 = compute_witness(
        current_public_input.clone(),
        private_inputs[0].clone(),
        witness_generator_file.clone(),
        &witness_generator_output,
    );

    let circuit_0 = CircomCircuit {
        r1cs: r1cs.clone(),
        witness: Some(witness_0),
    };
    let circuit_secondary = TrivialCircuit::default();
    let z0_secondary = vec![<GrumpkinEngine as Engine>::Scalar::ZERO];

    let mut recursive_snark = RecursiveSNARK::<E1, E2, C1, C2>::new(
        &pp,
        &circuit_0,
        &circuit_secondary,
        &start_public_input,
        &z0_secondary,
    ).unwrap();

    for i in 0..iteration_count {
        let witness = compute_witness(
            current_public_input.clone(),
            private_inputs[i].clone(),
            witness_generator_file.clone(),
            &witness_generator_output,
        );

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let res = recursive_snark.prove_step(
            &pp,
            &circuit,
            &circuit_secondary,
        );
        assert!(res.is_ok());
    }
    fs::remove_file(witness_generator_output)?;

    Ok(recursive_snark)
}

#[cfg(target_family = "wasm")]
pub async fn create_recursive_circuit<E1, E2>(
    witness_generator_file: FileLocation,
    r1cs: R1CS<F<E1>>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F<E1>>,
    pp: &PublicParams<E1, E2, C1, C2>,
) -> Result<RecursiveSNARK<E1, E2, C1, C2>, std::io::Error>
where
    E1: Group<Base = <E2 as Group>::Scalar>,
    E2: Group<Base = <E1 as Group>::Scalar>,
{

    let iteration_count = private_inputs.len();

    let start_public_input_hex = start_public_input
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();
    let mut current_public_input = start_public_input_hex.clone();

    let witness_0 = compute_witness::<E1, E2>(
        current_public_input.clone(),
        private_inputs[0].clone(),
        witness_generator_file.clone(),
    )
    .await;

    let circuit_0 = CircomCircuit {
        r1cs: r1cs.clone(),
        witness: Some(witness_0),
    };
    let circuit_secondary = TrivialCircuit::default();
    let z0_secondary = vec![E2::Scalar::ZERO];

    let mut recursive_snark = RecursiveSNARK::<E1, E2, C1, C2>::new(
        &pp,
        &circuit_0,
        &circuit_secondary,
        start_public_input.clone(),
        z0_secondary.clone(),
    );

    for i in 0..iteration_count {
        let witness = compute_witness::<E1, E2>(
            current_public_input.clone(),
            private_inputs[i].clone(),
            witness_generator_file.clone(),
        )
        .await;

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let res = recursive_snark.prove_step(
            &pp,
            &circuit,
            &circuit_secondary,
            start_public_input.clone(),
            z0_secondary.clone(),
        );
        assert!(res.is_ok());
    }

    Ok(recursive_snark)
}

#[cfg(not(target_family = "wasm"))]
pub fn continue_recursive_circuit(
    recursive_snark: &mut RecursiveSNARK<E1, E2, C1, C2>,
    last_zi: Vec<F>,
    witness_generator_file: FileLocation,
    r1cs: R1CS<F>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F>,
    pp: &PublicParams<E1, E2, C1, C2>,
) -> Result<(), std::io::Error>
{
    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");

    let iteration_count = private_inputs.len();

    let mut current_public_input = last_zi
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();

    let circuit_secondary = TrivialCircuit::default();
    let z0_secondary = vec![<Bn256Engine as Engine>::Scalar::ZERO];

    for i in 0..iteration_count {
        let witness = compute_witness(
            current_public_input.clone(),
            private_inputs[i].clone(),
            witness_generator_file.clone(),
            &witness_generator_output,
        );

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let res = recursive_snark.prove_step(
            pp,
            &circuit,
            &circuit_secondary,
        );

        assert!(res.is_ok());
    }

    fs::remove_file(witness_generator_output)?;

    Ok(())
}

#[cfg(target_family = "wasm")]
pub async fn continue_recursive_circuit<E1, E2>(
    recursive_snark: &mut RecursiveSNARK<E1, E2, C1, C2>,
    last_zi: Vec<F<E1>>,
    witness_generator_file: FileLocation,
    r1cs: R1CS<F<E1>>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F<E1>>,
    pp: &PublicParams<E1, E2, C1, C2>,
) -> Result<(), std::io::Error>
where
    E1: Group<Base = <E2 as Group>::Scalar>,
    E2: Group<Base = <E1 as Group>::Scalar>,
{
    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");

    let iteration_count = private_inputs.len();

    let mut current_public_input = last_zi
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();

    let circuit_secondary = TrivialCircuit::default();
    let z0_secondary = vec![E2::Scalar::ZERO];

    for i in 0..iteration_count {
        let witness = compute_witness::<E1, E2>(
            current_public_input.clone(),
            private_inputs[i].clone(),
            witness_generator_file.clone(),
        )
        .await;

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let res = recursive_snark.prove_step(
            pp,
            &circuit,
            &circuit_secondary,
            start_public_input.clone(),
            z0_secondary.clone(),
        );

        assert!(res.is_ok());
    }

    fs::remove_file(witness_generator_output)?;

    Ok(())
}
