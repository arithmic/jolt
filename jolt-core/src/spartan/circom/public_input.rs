use crate::{field::JoltField, spartan::{r1csinstance::R1CSInstance, spartan_memory_checking::SpartanPreprocessing, Instance}};

use super::non_native::{convert_vec_to_fqq, Fqq};
use ark_bn254::{ Bn254, Fr as Scalar, Fq as Fp };

