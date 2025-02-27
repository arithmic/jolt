use ark_bn254::Fq;
use ark_ff::{AdditiveGroup, Field};
use std::ops::Add;
use std::ops::Mul;

fn combine_limbs(l0: Fq, l1: Fq, l2: Fq) -> Fq {
    let two = Fq::from(2);
    l0 + (l1 * two.pow([125])) + (l2 * two.pow([250]))
}

fn evals(r: Vec<Fq>) -> Vec<Fq> {
    let ell = r.len();
    let pow_2 = 1 << ell;

    let mut temp: Vec<Vec<Fq>> = vec![vec![Fq::ZERO; pow_2]; ell + 1];
    temp[0][0] = Fq::ONE;

    let mut size = 1;
    for j in 0..ell {
        size *= 2;
        for i in (0..size).step_by(2) {
            temp[j][i] = temp[j][i / 2] * r[j];
            temp[j + 1][i + 1] = temp[j][i / 2] - temp[j + 1][i];
        }
    }

    let mut output = vec![Fq::ZERO; pow_2];
    for i in 0..pow_2 {
        output[i] = temp[ell][pow_2 - i - 1];
    }

    output
}

fn inner_product(a: Vec<Fq>, b: Vec<Fq>) -> Fq {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn verify_postponed_eval(input: Vec<Fq>, vec_to_eval_len: usize, l: usize) {
    let postponed_eval = &input[1..3 * l + 1];
    let vec_to_eval = &input[3 * l + 1..];

    let compressed_postponed_eval: Vec<Fq> = postponed_eval
        .chunks(3)
        .map(|chunk| combine_limbs(chunk[0], chunk[1], chunk[2]))
        .collect();
    let (pt, eval) = (
        compressed_postponed_eval[..compressed_postponed_eval.len() - 1].to_vec(),
        compressed_postponed_eval[compressed_postponed_eval.len() - 1],
    );

    let (vec_to_eval1, vec_to_eval2) = (
        vec_to_eval[..vec_to_eval.len() - 60].to_vec(),
        vec_to_eval[vec_to_eval.len() - 60..].to_vec(),
    );

    let comms: Vec<Fq> = vec_to_eval2
        .chunks(3)
        .map(|chunk| combine_limbs(chunk[0], chunk[1], chunk[2]))
        .collect();

    let mut pub_io = [vec_to_eval1, comms].concat();
    let pad_length = pub_io.len().checked_next_power_of_two().unwrap();
    let log_pad_length = (64 - (pad_length as u64).leading_zeros() - 1) as usize;

    pub_io.resize(pad_length, Fq::ZERO);

    let required_pt = pt[pt.len() - log_pad_length..].to_vec();
    let evals = evals(required_pt);

    let computed_eval = inner_product(pub_io, evals);

    assert_eq!(eval, computed_eval);
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use ark_bn254::Fq;
    use num_bigint::BigUint;
    use serde_json::Value;

    use super::verify_postponed_eval;

    #[test]
    fn test_postponed_eval() {
        let witness_file_path =
            "/Users/anujsharma/code/jolt/jolt-core/src/test_circom_jolt1/witness.json";
        let mut witness_file = File::open(witness_file_path).expect("Failed to open witness.json");

        let mut witness_contents = String::new();
        witness_file
            .read_to_string(&mut witness_contents)
            .expect("Failed to read witness.json");

        let witness_json: Value =
            serde_json::from_str(&witness_contents).expect("Failed to parse witness.json");

        if let Some(witness_array) = witness_json.as_array() {
            let result: Vec<Fq> = witness_array
                .iter()
                .take(1756)
                .map(|entry| entry.as_str().map(|s| s.to_string()).unwrap())
                .map(|entry| Fq::from(BigUint::parse_bytes(entry.as_bytes(), 10).unwrap()))
                .collect();

            verify_postponed_eval(result, 0, 24);
        } else {
            eprintln!("The JSON is not an array or 'witness' field is missing");
        }
    }
}
