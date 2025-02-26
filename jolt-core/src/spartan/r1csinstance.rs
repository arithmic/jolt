#![allow(dead_code)]
use super::sparse_mlpoly::SparseMatPolynomial;
use crate::{
    field::JoltField, poly::dense_mlpoly::DensePolynomial, spartan::sparse_mlpoly::SparseMatEntry,
    utils::math::Math,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sha3::Digest;
use sha3::Sha3_256;

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSInstance<F: JoltField> {
    num_cons: usize,
    num_vars: usize,
    num_inputs: usize,
    A: SparseMatPolynomial<F>,
    B: SparseMatPolynomial<F>,
    C: SparseMatPolynomial<F>,
}

impl<F: JoltField> R1CSInstance<F> {
    pub fn new(
        num_cons: usize,
        num_vars: usize,
        num_inputs: usize,
        A: SparseMatPolynomial<F>,
        B: SparseMatPolynomial<F>,
        C: SparseMatPolynomial<F>,
    ) -> R1CSInstance<F> {
        // check that num_cons is a power of 2
        assert_eq!(num_cons.next_power_of_two(), num_cons);

        // check that num_vars is a power of 2
        assert_eq!(num_vars.next_power_of_two(), num_vars);

        // check that number_inputs + 1 <= num_vars
        assert!(num_inputs < num_vars);

        Self {
            num_cons,
            num_vars,
            num_inputs,
            A,
            B,
            C,
        }
    }

    pub fn get_num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn get_num_cons(&self) -> usize {
        self.num_cons
    }

    pub fn get_num_inputs(&self) -> usize {
        self.num_inputs
    }

    pub fn get_matrices(&self) -> [&SparseMatPolynomial<F>; 3] {
        [&self.A, &self.B, &self.C]
    }

    pub fn get_digest(&self) -> F {
        let mut hash_bytes = Vec::new();
        self.serialize_compressed(&mut hash_bytes).unwrap();

        let mut hasher = Sha3_256::new();
        hasher.update(hash_bytes);

        let map_to_field = |digest: &[u8]| -> F {
            let bv = (0..250).map(|i| {
                let (byte_pos, bit_pos) = (i / 8, i % 8);
                let bit = (digest[byte_pos] >> bit_pos) & 1;
                bit == 1
            });

            // turn the bit vector into a scalar
            let mut digest = F::zero();
            let mut coeff = F::one();
            for bit in bv {
                if bit {
                    digest += coeff;
                }
                coeff += coeff;
            }
            digest
        };
        map_to_field(&hasher.finalize())
    }

    pub fn produce_synthetic_r1cs(
        num_cons: usize,
        num_vars: usize,
        num_inputs: usize,
    ) -> (R1CSInstance<F>, Vec<F>, Vec<F>) {
        let mut rng = ChaCha8Rng::from_seed([2; 32]);

        // assert num_cons and num_vars are power of 2
        assert_eq!((num_cons.log_2()).pow2(), num_cons);
        assert_eq!((num_vars.log_2()).pow2(), num_vars);

        // num_inputs + 1 <= num_vars
        assert!(num_inputs < num_vars);

        let append_zeroes = num_vars - num_inputs - 1;

        // z is organized as [vars,1,io]
        let size_z = append_zeroes + num_vars + num_inputs + 1;

        // produce a random satisfying assignment
        let Z = {
            let mut Z = vec![F::zero(); size_z];
            Z[0] = F::one(); // set the constant term to 1
            Z.iter_mut()
                .take(num_inputs + 1)
                .skip(1)
                .for_each(|z| *z = F::random::<ChaCha8Rng>(&mut rng));
            Z.iter_mut()
                .skip(append_zeroes + num_inputs + 1)
                .for_each(|z| *z = F::random::<ChaCha8Rng>(&mut rng));
            Z
        };
        // three sparse matrices
        let mut A: Vec<SparseMatEntry<F>> = Vec::new();
        let mut B: Vec<SparseMatEntry<F>> = Vec::new();
        let mut C: Vec<SparseMatEntry<F>> = Vec::new();
        let one = F::one();
        for i in 0..num_cons {
            let A_idx = i % size_z;
            let B_idx = (i + 2) % size_z;
            A.push(SparseMatEntry::new(i, A_idx, one));
            B.push(SparseMatEntry::new(i, B_idx, one));
            let AB_val = Z[A_idx] * Z[B_idx];

            let C_idx = (i + 3) % size_z;
            let C_val = Z[C_idx];

            if C_val == F::zero() {
                C.push(SparseMatEntry::new(i, 0, AB_val));
            } else {
                C.push(SparseMatEntry::new(
                    i,
                    C_idx,
                    AB_val * C_val.inverse().unwrap(),
                ));
            }
        }
        let num_poly_vars_x = num_cons.next_power_of_two().log_2();
        let num_poly_vars_y = size_z.next_power_of_two().log_2();
        let poly_A = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, A);
        let poly_B = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, B);
        let poly_C = SparseMatPolynomial::new(num_poly_vars_x, num_poly_vars_y, C);

        let inst = R1CSInstance {
            num_cons,
            num_vars,
            num_inputs,
            A: poly_A,
            B: poly_B,
            C: poly_C,
        };

        assert!(inst.is_sat(&Z[1..num_inputs + 1], &Z[num_inputs + append_zeroes + 1..]));

        (
            inst,
            Z[1..num_inputs + 1].to_vec(),
            Z[num_inputs + append_zeroes + 1..].to_vec(),
        )
    }

    pub fn is_sat(&self, input: &[F], vars: &[F]) -> bool {
        assert_eq!(vars.len(), self.num_vars);
        assert_eq!(input.len(), self.num_inputs);

        let append_zeroes = self.num_vars - self.num_inputs - 1;

        let z = {
            let mut z = vec![F::one()];
            z.extend(input);
            z.extend(&vec![F::zero(); append_zeroes]);
            z.extend(vars.to_vec());
            z
        };

        // verify if Az * Bz - Cz = [0...]
        let Az = self.A.multiply_vec(
            self.num_cons,
            self.num_vars + self.num_inputs + append_zeroes + 1,
            &z,
        );
        let Bz = self.B.multiply_vec(
            self.num_cons,
            self.num_vars + self.num_inputs + append_zeroes + 1,
            &z,
        );
        let Cz = self.C.multiply_vec(
            self.num_cons,
            self.num_vars + self.num_inputs + append_zeroes + 1,
            &z,
        );

        (0..self.num_cons).all(|i| Az[i] * Bz[i] == Cz[i])
    }

    pub fn multiply_vec(
        &self,
        num_rows: usize,
        num_cols: usize,
        z: &[F],
    ) -> (DensePolynomial<F>, DensePolynomial<F>, DensePolynomial<F>) {
        assert_eq!(num_rows, self.num_cons);
        assert_eq!(z.len(), num_cols);
        assert!(num_cols > self.num_vars);
        (
            DensePolynomial::new(self.A.multiply_vec(num_rows, num_cols, z)),
            DensePolynomial::new(self.B.multiply_vec(num_rows, num_cols, z)),
            DensePolynomial::new(self.C.multiply_vec(num_rows, num_cols, z)),
        )
    }

    pub fn compute_eval_table_sparse(
        &self,
        num_rows: usize,
        num_cols: usize,
        evals: &[F],
    ) -> (Vec<F>, Vec<F>, Vec<F>) {
        assert_eq!(num_rows, self.num_cons);
        assert!(num_cols > self.num_vars);

        let evals_A = self.A.compute_eval_table_sparse(evals, num_rows, num_cols);
        let evals_B = self.B.compute_eval_table_sparse(evals, num_rows, num_cols);
        let evals_C = self.C.compute_eval_table_sparse(evals, num_rows, num_cols);

        (evals_A, evals_B, evals_C)
    }

    pub fn evaluate(&self, rx: &[F], ry: &[F]) -> (F, F, F) {
        let evals = SparseMatPolynomial::multi_evaluate(&[&self.A, &self.B, &self.C], rx, ry);
        (evals[0], evals[1], evals[2])
    }
}
