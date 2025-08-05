package pcs

import (
	"fmt"
	"strconv"

	"github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"

	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"

	"github.com/arithmic/jolt/jolt-on-chain/circuits/uniform"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type DoryVerifierFinalStep struct {
	C  GT
	D1 GT
	D2 GT
	E1 groups.G1Projective
	E2 groups.G2Projective

	Chi            frontend.Variable
	Gamma1         groups.G1Projective
	D_times_Gamma1 groups.G1Projective

	Gamma2           groups.G2Projective
	DInvTimes_Gamma2 groups.G2Projective

	V1 groups.G1Projective
	V2 groups.G2Projective

	D     frontend.Variable
	S     []frontend.Variable
	R     []frontend.Variable
	Alpha []frontend.Variable

	Pairing_final_res field_tower.Fp12
}

func (circuit *DoryVerifierFinalStep) Define(api frontend.API) error {
	//  e(v_1 + d * gamma_1 , v_2 + d^{-1} * gamma_2) computation is done in Pairing circuit

	g1_api := groups.NewG1API(api)

	// d_gamma1 := g1_api.ScalarMul(&circuit.Gamma1, &circuit.D)

	g2_api := groups.New(api)
	d_inverse := api.Inverse(circuit.D)
	// d_inverse_gamma2 := g2_api.Mul(&circuit.Gamma2, &d_inverse)

	_ = g1_api.Add(&circuit.V1, &circuit.D_times_Gamma1)
	_ = g2_api.Add(&circuit.V2, &circuit.DInvTimes_Gamma2)

	// v2_plus_d_inverse_gamma2_affine := groups.ToAffine(&v2_plus_d_inverse_gamma2)
	// pairing_api := pairing.New(api)
	// e1 := pairing_api.Pairing(&v2_plus_d_inverse_gamma2, v1_plus_d_gamma1)

	// Computing  Chi + C + d * D2 + d^{-1} * D1
	gt_api := field_tower.NewExt12(api)
	chi_c := gt_api.Fp12MulFp(&circuit.C, circuit.Chi)
	d_d2 := gt_api.Fp12MulFp(&circuit.D2, circuit.D)
	d_inverse_d1 := gt_api.Fp12MulFp(&circuit.D1, d_inverse)
	chi_c_plus_d_d2 := gt_api.Add(chi_c, d_d2)
	_ = gt_api.Add(chi_c_plus_d_d2, d_inverse_d1)
	// chi_c_plus_d_d2_plus_d_inverse_d1 := gt_api.Add(chi_c_plus_d_d2, d_inverse_d1)
	_ = gt_api.Add(chi_c_plus_d_d2, d_inverse_d1)
	// gt_api.AssertIsEqual(chi_c_plus_d_d2_plus_d_inverse_d1, &circuit.Pairing_final_res)

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

	_ = g1_api.ScalarMul(&circuit.V1, &computed_alpha_s)
	_ = g2_api.Mul(&circuit.V2, &computed_alpha_r)

	// g1_api.AssertIsEqual(&circuit.E1, computed_e1)
	// g2_api.AssertIsEqual(&circuit.E2, computed_e2)

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

// DoryVerifierFinalStep Uniform Circuit
type DoryVerifierFinalStepUniform struct {
	C  GT
	D1 GT
	D2 GT
	E1 groups.G1Projective
	E2 groups.G2Projective

	Chi            frontend.Variable
	Gamma1         groups.G1Projective
	D_times_Gamma1 groups.G1Projective

	Gamma2           groups.G2Projective
	DInvTimes_Gamma2 groups.G2Projective

	V1 groups.G1Projective
	V2 groups.G2Projective

	D     frontend.Variable
	S     []frontend.Variable
	R     []frontend.Variable
	Alpha []frontend.Variable

	Pairing_final_res field_tower.Fp12

	Step *DoryVerifierFinalStep
}

func (g2MultiMul *DoryVerifierFinalStepUniform) GetConstraints() uniform.UniformR1CS {
	var constraints []uniform.Constraint
	var aCount, bCount, cCount int

	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, g2MultiMul.Step)
	if err != nil {
		fmt.Println("err in compilation is ", err)
	}

	nR1CS, ok := r1cs.(constraint.R1CS)
	if !ok {
		return uniform.UniformR1CS{
			Constraints: constraints,
			ACount:      0,
			BCount:      0,
			CCount:      0,
			NumSteps:    0}
	}

	cs := nR1CS.GetR1Cs()
	for _, r1c := range cs {
		singular := uniform.Constraint{
			A: make(map[string]string),
			B: make(map[string]string),
			C: make(map[string]string),
		}

		for _, term := range r1c.L {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.A[col] = val
			aCount++
		}
		for _, term := range r1c.R {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.B[col] = val
			bCount++
		}
		for _, term := range r1c.O {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.C[col] = val
			cCount++
		}

		constraints = append(constraints, singular)
	}

	return uniform.UniformR1CS{
		Constraints: constraints,
		ACount:      uint32(aCount),
		BCount:      uint32(bCount),
		CCount:      uint32(cCount),
		NumSteps:    uint32(1),
	}
}

func (stepcircuit *DoryVerifierFinalStepUniform) CreateStepCircuit() constraint.ConstraintSystem {

	cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, stepcircuit.Step)
	if err != nil {
		panic(err)
	}
	return cs
}

// GenerateWitness generates the witness for the final step circuit
func (circuit *DoryVerifierFinalStepUniform) GenerateWitness(constraints constraint.ConstraintSystem) fr.Vector {
	var witness fr.Vector

	circuit.Step.C = circuit.C
	circuit.Step.D1 = circuit.D1
	circuit.Step.D2 = circuit.D2
	circuit.Step.E1 = circuit.E1
	circuit.Step.E2 = circuit.E2

	circuit.Step.Chi = circuit.Chi
	circuit.Step.Gamma1 = circuit.Gamma1
	circuit.Step.D_times_Gamma1 = circuit.D_times_Gamma1
	circuit.Step.Gamma2 = circuit.Gamma2
	circuit.Step.DInvTimes_Gamma2 = circuit.DInvTimes_Gamma2
	circuit.Step.V1 = circuit.V1
	circuit.Step.V2 = circuit.V2
	circuit.Step.D = circuit.D
	circuit.Step.S = circuit.S
	circuit.Step.R = circuit.R
	circuit.Step.Alpha = circuit.Alpha
	circuit.Step.Pairing_final_res = circuit.Pairing_final_res

	witness = circuit.Step.GenerateWitness(constraints)

	return witness
}
