package pcs

import (
	"fmt"
	"math/big"

	"github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"

	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type GT = field_tower.Fp12

type DoryVerifierStep struct {
	C        GT
	D1       GT
	D2       GT
	Delta1_L GT
	Delta1_R GT
	Delta2_L GT
	Delta2_R GT

	Chi frontend.Variable

	D1_L GT
	D1_R GT
	D2_L GT
	D2_R GT
	Beta frontend.Variable

	C_Plus  GT
	C_Minus GT
	Alpha   frontend.Variable

	C_Prime               GT
	Beta_D2               GT
	Beta_Inverse_D1       GT
	Alpha_C_PLUS          GT
	Alpha_Inverse_C_MINUS GT

	D1_Prime            GT
	Alpha_D1_L          GT
	Alpha_Beta_Delta1_L GT
	Beta_Delta1_R       GT

	D2_Prime                            GT
	Alpha_Inverse_D2_L                  GT
	Alpha_Inverse_Beta_Inverse_Delta2_L GT
	Beta_Inverse_Delta2_R               GT

	E1       groups.G1Projective
	E2       groups.G2Projective
	E1_Beta  groups.G1Projective
	E2_Beta  groups.G2Projective
	E1_PLUS  groups.G1Projective
	E1_MINUS groups.G1Projective
	E2_PLUS  groups.G2Projective
	E2_MINUS groups.G2Projective

	E1_Prime groups.G1Projective
	E2_Prime groups.G2Projective
}

func (circuit *DoryVerifierStep) Define(api frontend.API) error {

	gt_api := field_tower.NewExt12(api)

	// Computing C_prime
	C_prime_temp_1 := gt_api.Mul(&circuit.Alpha_C_PLUS, &circuit.Alpha_Inverse_C_MINUS)
	C_prime_temp_2 := gt_api.Fp12MulFp(&circuit.C, circuit.Chi)
	C_prime_temp_3 := gt_api.Mul(&circuit.Beta_D2, &circuit.Beta_Inverse_D1)
	C_prime_temp_4 := gt_api.Mul(C_prime_temp_1, C_prime_temp_2)
	C_prime := gt_api.Mul(C_prime_temp_4, C_prime_temp_3)
	gt_api.AssertIsEqual(&circuit.C_Prime, C_prime)

	// Computing  D1_Prime
	D1_Prime_temp_1 := gt_api.Mul(&circuit.Alpha_D1_L, &circuit.D1_R)
	D1_Prime_temp_2 := gt_api.Mul(&circuit.Alpha_Beta_Delta1_L, &circuit.Beta_Delta1_R)
	D1_Prime := gt_api.Mul(D1_Prime_temp_1, D1_Prime_temp_2)
	gt_api.AssertIsEqual(&circuit.D1_Prime, D1_Prime)

	// Computing  D2_Prime
	D2_Prime_temp_1 := gt_api.Mul(&circuit.Alpha_Inverse_D2_L, &circuit.D2_R)
	D2_Prime_temp_2 := gt_api.Mul(&circuit.Alpha_Inverse_Beta_Inverse_Delta2_L, &circuit.Beta_Inverse_Delta2_R)
	D2_Prime := gt_api.Mul(D2_Prime_temp_1, D2_Prime_temp_2)
	gt_api.AssertIsEqual(&circuit.D2_Prime, D2_Prime)

	// Computing E1_Prime
	g1_api := groups.G1API{api}
	beta_E1_beta := g1_api.ScalarMul(&circuit.E1_Beta, &circuit.Beta)
	E1_Prime_temp_1 := g1_api.Add(&circuit.E1, beta_E1_beta)
	alpha_E1 := g1_api.ScalarMul(&circuit.E1_PLUS, &circuit.Alpha)
	alpha_inverse := api.Inverse(circuit.Alpha)
	alpha_inverse_E1_minus := g1_api.ScalarMul(&circuit.E1_MINUS, &alpha_inverse)
	E1_Prime_temp_2 := g1_api.Add(alpha_E1, alpha_inverse_E1_minus)
	E1_Prime := g1_api.Add(E1_Prime_temp_1, E1_Prime_temp_2)
	g1_api.AssertIsEqual(&circuit.E1_Prime, E1_Prime)

	// Computing E2_Prime
	g2_api := groups.New(api)
	beta_inverse := api.Inverse(circuit.Beta)
	beta_inverse_E2_beta := g2_api.Mul(&circuit.E2_Beta, &beta_inverse)
	E2_Prime_temp_1 := g2_api.Add(&circuit.E2, beta_inverse_E2_beta)
	alpha_E2 := g2_api.Mul(&circuit.E2_PLUS, &circuit.Alpha)

	alpha_inverse_E2_minus := g2_api.Mul(&circuit.E2_MINUS, &alpha_inverse)
	E2_Prime_temp_2 := g2_api.Add(alpha_E2, alpha_inverse_E2_minus)
	E2_Prime := g2_api.Add(E2_Prime_temp_1, E2_Prime_temp_2)
	g2_api.AssertIsEqual(&circuit.E2_Prime, E2_Prime)
	return nil

}

func (circuit *DoryVerifierStep) Hint() {

	// Computing C_prime
	var C_prime bn254.E12
	chi, _ := utils.FrontendVariableToFrElement(circuit.Chi)
	beta, _ := utils.FrontendVariableToFrElement(circuit.Beta)
	d2 := field_tower.ToE12(circuit.D2)
	var beta_d2 bn254.E12
	var betaBigInt big.Int
	beta.BigInt(&betaBigInt)
	beta_d2.Exp(d2, &betaBigInt)

	circuit.Beta_D2 = field_tower.FromE12(&beta_d2)

	C_prime = MulByElement(field_tower.ToE12(circuit.C), chi)

	C_prime.Mul(&beta_d2, &C_prime)

	var beta_inverse fr.Element
	beta_inverse.Inverse(&beta)

	var beta_inverse_bigint big.Int
	beta_inverse.BigInt(&beta_inverse_bigint)
	d1 := field_tower.ToE12(circuit.D1)
	var beta_inverse_d1 bn254.E12
	beta_inverse_d1.Exp(d1, &beta_inverse_bigint)
	circuit.Beta_Inverse_D1 = field_tower.FromE12(&beta_inverse_d1)

	C_prime.Mul(&beta_inverse_d1, &C_prime)

	alpha, _ := utils.FrontendVariableToFrElement(circuit.Alpha)
	var alpha_bigint big.Int
	alpha.BigInt(&alpha_bigint)

	var alpha_inverse fr.Element
	alpha_inverse.Inverse(&alpha)
	var alpha_inverse_bigint big.Int
	alpha_inverse.BigInt(&alpha_inverse_bigint)

	c_plus := field_tower.ToE12(circuit.C_Plus)
	var alpha_c_plus bn254.E12
	alpha_c_plus.Exp(c_plus, &alpha_bigint)
	circuit.Alpha_C_PLUS = field_tower.FromE12(&alpha_c_plus)

	C_prime.Mul(&alpha_c_plus, &C_prime)

	c_minus := field_tower.ToE12(circuit.C_Minus)
	var alpha_inverse_c_minus bn254.E12
	alpha_inverse_c_minus.Exp(c_minus, &alpha_inverse_bigint)
	circuit.Alpha_Inverse_C_MINUS = field_tower.FromE12(&alpha_inverse_c_minus)

	C_prime.Mul(&alpha_inverse_c_minus, &C_prime)
	circuit.C_Prime = field_tower.FromE12(&C_prime)

	// // Computing D1_prime
	d1L := field_tower.ToE12(circuit.D1_L)
	var alpha_d1_l bn254.E12
	alpha_d1_l.Exp(d1L, &alpha_bigint)
	circuit.Alpha_D1_L = field_tower.FromE12(&alpha_d1_l)

	var alpha_beta fr.Element
	alpha_beta.Mul(&alpha, &beta)

	var alphaBetaDelta1L bn254.E12
	delta1L := field_tower.ToE12(circuit.Delta1_L)
	var alpha_beta_bigint big.Int
	alpha_beta.BigInt(&alpha_beta_bigint)
	alphaBetaDelta1L.Exp(delta1L, &alpha_beta_bigint)
	circuit.Alpha_Beta_Delta1_L = field_tower.FromE12(&alphaBetaDelta1L)

	delta1R := field_tower.ToE12(circuit.Delta1_R)
	var betaDelta1R bn254.E12
	betaDelta1R.Exp(delta1R, &betaBigInt)
	circuit.Beta_Delta1_R = field_tower.FromE12(&betaDelta1R)

	var D1_prime bn254.E12
	d1R := field_tower.ToE12(circuit.D1_R)

	D1_prime.Mul(&alpha_d1_l, &d1R)
	D1_prime.Mul(&alphaBetaDelta1L, &D1_prime)
	D1_prime.Mul(&betaDelta1R, &D1_prime)
	circuit.D1_Prime = field_tower.FromE12(&D1_prime)

	// Computing D2_prime
	var D2_prime bn254.E12
	d2L := field_tower.ToE12(circuit.D2_L)
	var alphaInverseD2L bn254.E12
	alphaInverseD2L.Exp(d2L, &alpha_inverse_bigint)
	circuit.Alpha_Inverse_D2_L = field_tower.FromE12(&alphaInverseD2L)

	d2R := field_tower.ToE12(circuit.D2_R)
	var alphaInverseBetaInverse fr.Element
	alphaInverseBetaInverse.Mul(&alpha_inverse, &beta_inverse)
	var alphaInverseBetaInverseBigInt big.Int
	alphaInverseBetaInverse.BigInt(&alphaInverseBetaInverseBigInt)
	var alphaInverseBetaInverseDelta2L bn254.E12
	delta2L := field_tower.ToE12(circuit.Delta2_L)
	alphaInverseBetaInverseDelta2L.Exp(delta2L, &alphaInverseBetaInverseBigInt)
	circuit.Alpha_Inverse_Beta_Inverse_Delta2_L = field_tower.FromE12(&alphaInverseBetaInverseDelta2L)

	var betaInverseDelta2R bn254.E12
	delta2R := field_tower.ToE12(circuit.Delta2_R)
	betaInverseDelta2R.Exp(delta2R, &beta_inverse_bigint)
	circuit.Beta_Inverse_Delta2_R = field_tower.FromE12(&betaInverseDelta2R)

	D2_prime.Mul(&alphaInverseD2L, &d2R)
	D2_prime.Mul(&alphaInverseBetaInverseDelta2L, &D2_prime)
	D2_prime.Mul(&betaInverseDelta2R, &D2_prime)
	circuit.D2_Prime = field_tower.FromE12(&D2_prime)

	// Computing E1_prime
	var E1_prime bn254.G1Affine
	e1_beta := groups.To_Bn254G1Affine(circuit.E1_Beta)

	E1_prime.ScalarMultiplication(&e1_beta, &betaBigInt)

	e1 := groups.To_Bn254G1Affine(circuit.E1)
	E1_prime.Add(&E1_prime, &e1)

	var alpha_e1 bn254.G1Affine
	e1_plus := groups.To_Bn254G1Affine(circuit.E1_PLUS)
	alpha_e1.ScalarMultiplication(&e1_plus, &alpha_bigint)
	E1_prime.Add(&E1_prime, &alpha_e1)

	var alpha_inverse_e1_minus bn254.G1Affine
	e1_minus := groups.To_Bn254G1Affine(circuit.E1_MINUS)
	alpha_inverse_e1_minus.ScalarMultiplication(&e1_minus, &alpha_inverse_bigint)
	E1_prime.Add(&E1_prime, &alpha_inverse_e1_minus)

	circuit.E1_Prime = groups.FromG1Affine(&E1_prime)

	// Computing E2_prime
	var E2_prime bn254.G2Affine
	e2_beta := groups.To_Bn254G2Affine(circuit.E2_Beta)

	var beta_inverse_e2_beta bn254.G2Affine
	beta_inverse_e2_beta.ScalarMultiplication(&e2_beta, &beta_inverse_bigint)

	e2 := groups.To_Bn254G2Affine(circuit.E2)
	E2_prime.Add(&e2, &beta_inverse_e2_beta)

	var alpha_e2_plus bn254.G2Affine
	e2_plus := groups.To_Bn254G2Affine(circuit.E2_PLUS)

	alpha_e2_plus.ScalarMultiplication(&e2_plus, &alpha_bigint)
	E2_prime.Add(&E2_prime, &alpha_e2_plus)

	var alpha_inverse_e2_minus bn254.G2Affine
	e2_minus := groups.To_Bn254G2Affine(circuit.E2_MINUS)
	alpha_inverse_e2_minus.ScalarMultiplication(&e2_minus, &alpha_inverse_bigint)
	E2_prime.Add(&E2_prime, &alpha_inverse_e2_minus)

	circuit.E2_Prime = groups.FromBNG2Affine(&E2_prime)

}

func (circuit *DoryVerifierStep) GenerateWitness(constraints constraint.ConstraintSystem) fr.Vector {
	w, err := frontend.NewWitness(circuit, ecc.GRUMPKIN.ScalarField())

	if err != nil {
		fmt.Println("Failed to create witness object", err)
	}
	wit, err := constraints.Solve(w)
	if err != nil {
		fmt.Println("Witness generation failed ", err)
	}
	wSolved := wit.(*cs.R1CSSolution).W

	return wSolved
}

type DoryVerifier struct {
	C  GT
	D1 GT
	D2 GT
	E1 groups.G1Projective
	E2 groups.G2Projective

	Alpha    []frontend.Variable
	Beta     []frontend.Variable
	Chi      []frontend.Variable
	C_Plus   []GT
	C_Minus  []GT
	D1_L     []GT
	D1_R     []GT
	D2_L     []GT
	D2_R     []GT
	Delta1_L []GT
	Delta1_R []GT
	Delta2_L []GT
	Delta2_R []GT

	E1_Beta  []groups.G1Projective
	E1_PLUS  []groups.G1Projective
	E1_MINUS []groups.G1Projective
	E2_Beta  []groups.G2Projective
	E2_PLUS  []groups.G2Projective
	E2_MINUS []groups.G2Projective

	doryverifierstep *DoryVerifierStep
}

func (dory_verifier *DoryVerifier) CreateStepCircuit() constraint.ConstraintSystem {

	doryVerifierConstraints, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, dory_verifier.doryverifierstep)

	return doryVerifierConstraints

}

func (dory_verifier *DoryVerifier) GenerateWitness(constraints constraint.ConstraintSystem) fr.Vector {

	n := len(dory_verifier.Alpha)
	var witness fr.Vector

	dory_verifier.doryverifierstep = &DoryVerifierStep{
		C:  dory_verifier.C,
		D1: dory_verifier.D1,
		D2: dory_verifier.D2,
		E1: dory_verifier.E1,
		E2: dory_verifier.E2,
	}

	for i := 0; i < n; i++ {
		dory_verifier.doryverifierstep.Alpha = dory_verifier.Alpha[i]
		dory_verifier.doryverifierstep.Beta = dory_verifier.Beta[i]
		dory_verifier.doryverifierstep.Chi = dory_verifier.Chi[i]
		dory_verifier.doryverifierstep.C_Plus = dory_verifier.C_Plus[i]
		dory_verifier.doryverifierstep.C_Minus = dory_verifier.C_Minus[i]
		dory_verifier.doryverifierstep.D1_L = dory_verifier.D1_L[i]
		dory_verifier.doryverifierstep.D1_R = dory_verifier.D1_R[i]
		dory_verifier.doryverifierstep.D2_L = dory_verifier.D2_L[i]
		dory_verifier.doryverifierstep.D2_R = dory_verifier.D2_R[i]
		dory_verifier.doryverifierstep.Delta1_L = dory_verifier.Delta1_L[i]
		dory_verifier.doryverifierstep.Delta1_R = dory_verifier.Delta1_R[i]
		dory_verifier.doryverifierstep.Delta2_L = dory_verifier.Delta2_L[i]
		dory_verifier.doryverifierstep.Delta2_R = dory_verifier.Delta2_R[i]
		dory_verifier.doryverifierstep.E1_Beta = dory_verifier.E1_Beta[i]
		dory_verifier.doryverifierstep.E1_PLUS = dory_verifier.E1_PLUS[i]
		dory_verifier.doryverifierstep.E1_MINUS = dory_verifier.E1_MINUS[i]
		dory_verifier.doryverifierstep.E2_Beta = dory_verifier.E2_Beta[i]
		dory_verifier.doryverifierstep.E2_PLUS = dory_verifier.E2_PLUS[i]
		dory_verifier.doryverifierstep.E2_MINUS = dory_verifier.E2_MINUS[i]

		dory_verifier.doryverifierstep.Hint()
		stepWitness := dory_verifier.doryverifierstep.GenerateWitness(constraints)
		witness = append(witness, stepWitness...)

		dory_verifier.doryverifierstep.C = dory_verifier.doryverifierstep.C_Prime
		dory_verifier.doryverifierstep.D1 = dory_verifier.doryverifierstep.D1_Prime
		dory_verifier.doryverifierstep.D2 = dory_verifier.doryverifierstep.D2_Prime
		dory_verifier.doryverifierstep.E1 = dory_verifier.doryverifierstep.E1_Prime
		dory_verifier.doryverifierstep.E2 = dory_verifier.doryverifierstep.E2_Prime

	}

	return witness

}

type DoryVerifierFinalStep struct {
	C  GT
	D1 GT
	D2 GT
	E1 groups.G1Projective
	E2 groups.G2Projective

	Chi    frontend.Variable
	Gamma1 groups.G1Projective
	Gamma2 groups.G2Projective
	V1     groups.G1Projective
	V2     groups.G2Projective

	D     frontend.Variable
	S     []frontend.Variable
	R     []frontend.Variable
	Alpha []frontend.Variable
}

func (circuit *DoryVerifierFinalStep) Define(api frontend.API) error {

	// gt_api := field_tower.NewExt12(api)

	// // Computing e(v_1 + d * gamma_1 , v_2 + d^{-1} * gamma_2)

	g1_api := groups.G1API{api}

	// d_gamma1 := g1_api.ScalarMul(&circuit.Gamma1, &circuit.D)

	g2_api := groups.New(api)
	// d_inverse := api.Inverse(circuit.D)
	// d_inverse_gamma2 := g2_api.Mul(&circuit.Gamma2, &d_inverse)

	// v1_plus_d_gamma1 := g1_api.Add(&circuit.V1, d_gamma1)
	// v2_plus_d_inverse_gamma2 := g2_api.Add(&circuit.V2, d_inverse_gamma2)

	// // e1 := g1_api.Pairing(v1_plus_d_gamma1, &v2_plus_d_inverse_gamma2)

	// // Computing  Chi + C + d * D2 + d^{-1} * D1

	// chi_c := gt_api.Fp12MulFp(&circuit.C, circuit.Chi)
	// d_d2 := gt_api.Fp12MulFp(&circuit.D2, circuit.D)
	// d_inverse_d1 := gt_api.Fp12MulFp(&circuit.D1, d_inverse)
	// chi_c_plus_d_d2 := gt_api.Add(chi_c, d_d2)
	// chi_c_plus_d_d2_plus_d_inverse_d1 := gt_api.Add(chi_c_plus_d_d2, d_inverse_d1)

	// Computing e1 = prod_{i=0}^{n-1} (alpha_i * (1-s_i) + s_i )
	// computed_alpha_s := make([]frontend.Variable, len(circuit.s)+1)
	computed_alpha_s := frontend.Variable(1)

	computed_alpha_r := frontend.Variable(1)

	for i := 0; i < len(circuit.S); i++ {
		one_minus_si := api.Sub(1, circuit.S[i])
		one_minus_si_alpha_i := api.Mul(one_minus_si, circuit.Alpha[i])
		one_minus_si_alpha_i_plus_s_i := api.Add(one_minus_si_alpha_i, circuit.S[i])
		computed_alpha_s = api.Mul(computed_alpha_s, one_minus_si_alpha_i_plus_s_i)

		alpha_i_inverse := api.Inverse(circuit.Alpha[i])
		one_minus_ri := api.Sub(1, circuit.R[i])
		one_minus_ri_alpha_i_inverse := api.Mul(one_minus_ri, alpha_i_inverse)
		one_minus_ri_alpha_i_inverse_plus_r_i := api.Add(one_minus_ri_alpha_i_inverse, circuit.R[i])

		computed_alpha_r = api.Mul(computed_alpha_r, one_minus_ri_alpha_i_inverse_plus_r_i)
	}

	computed_e1 := g1_api.ScalarMul(&circuit.V1, &computed_alpha_s)
	computed_e2 := g2_api.Mul(&circuit.V2, &computed_alpha_r)

	g1_api.AssertIsEqual(&circuit.E1, computed_e1)
	g2_api.AssertIsEqual(&circuit.E2, computed_e2)

	return nil

}

func (circuit *DoryVerifierFinalStep) Compile() constraint.ConstraintSystem {

	circuitR1CS, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("err in compilation is ", err)
	}
	return circuitR1CS
}

func (circuit *DoryVerifierFinalStep) GenerateWitness(constraints constraint.ConstraintSystem) fr.Vector {

	var witness fr.Vector

	// Generate witness
	w, err := frontend.NewWitness(circuit, ecc.GRUMPKIN.ScalarField())
	if err != nil {
		fmt.Println("error generating witness:", err)
		return witness
	}

	wSolved, err := (constraints).Solve(w)
	if err != nil {
		fmt.Println("error solving R1CS:", err)
		return witness
	}

	witnessStep := wSolved.(*cs.R1CSSolution).W

	witness = append(witness, witnessStep...)

	return witness
}

// //////////////////////////////////
// Helper function
func MulByElement(x bn254.E12, element fr.Element) bn254.E12 {

	var result bn254.E12
	var elementFp fp.Element
	elementFp.SetBigInt(element.BigInt(new(big.Int)))

	result.C0.B0.A0.Mul(&x.C0.B0.A0, &elementFp)
	result.C0.B0.A1.Mul(&x.C0.B0.A1, &elementFp)
	result.C0.B1.A0.Mul(&x.C0.B1.A0, &elementFp)
	result.C0.B1.A1.Mul(&x.C0.B1.A1, &elementFp)
	result.C0.B2.A0.Mul(&x.C0.B2.A0, &elementFp)
	result.C0.B2.A1.Mul(&x.C0.B2.A1, &elementFp)
	result.C1.B0.A0.Mul(&x.C1.B0.A0, &elementFp)
	result.C1.B0.A1.Mul(&x.C1.B0.A1, &elementFp)
	result.C1.B1.A0.Mul(&x.C1.B1.A0, &elementFp)
	result.C1.B1.A1.Mul(&x.C1.B1.A1, &elementFp)
	result.C1.B2.A0.Mul(&x.C1.B2.A0, &elementFp)
	result.C1.B2.A1.Mul(&x.C1.B2.A1, &elementFp)
	return result

}
