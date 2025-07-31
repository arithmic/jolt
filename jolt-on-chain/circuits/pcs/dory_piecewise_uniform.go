package pcs

import (
	"github.com/arithmic/gnark/constraint"
	"github.com/arithmic/gnark/frontend"

	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"

	"github.com/arithmic/jolt/jolt-on-chain/circuits/uniform"

	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type DoryPieceWiseUniform struct {
	n  int
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

	Alpha_Inv_E1_Minus []groups.G1Projective
	Alpha_Inv_E2_Minus []groups.G2Projective

	E2_Beta  []groups.G2Projective
	E2_PLUS  []groups.G2Projective
	E2_MINUS []groups.G2Projective

	g1MultiMul  *uniform.G1MultiMul
	g2MultiMul  *uniform.G2MultiMul
	doryUniform *DoryVerifierUniform

	// Chi            frontend.Variable
	Gamma1         groups.G1Projective
	d_times_Gamma1 groups.G1Projective

	Gamma2           groups.G2Projective
	dInvTimes_Gamma2 groups.G2Projective

	V1 groups.G1Projective
	V2 groups.G2Projective

	D frontend.Variable
	S []frontend.Variable
	R []frontend.Variable

	finalstep *DoryVerifierFinalStepUniform
}

func (circuit *DoryPieceWiseUniform) Compile() []constraint.ConstraintSystem {
	var r1cs []constraint.ConstraintSystem
	return r1cs
}

func (circuit *DoryPieceWiseUniform) CreateStepCircuits() []constraint.ConstraintSystem {
	doryStepR1CS := circuit.doryUniform.CreateStepCircuit()
	g1R1CS := circuit.g1MultiMul.CreateStepCircuit()
	g2R1CS := circuit.g2MultiMul.CreateStepCircuit()
	final_stepR1CS := circuit.finalstep.CreateStepCircuit()

	stepCircuits := []constraint.ConstraintSystem{doryStepR1CS, g1R1CS, g2R1CS, final_stepR1CS}
	return stepCircuits
}

func (circuit *DoryPieceWiseUniform) GenerateWitness(constraints []constraint.ConstraintSystem) fr.Vector {

	var witness fr.Vector

	circuit.doryUniform = &DoryVerifierUniform{
		C:  circuit.C,
		D1: circuit.D1,
		D2: circuit.D2,
		E1: circuit.E1,
		E2: circuit.E2,
	}

	circuit.doryUniform.Alpha = circuit.Alpha
	circuit.doryUniform.Beta = circuit.Beta
	circuit.doryUniform.Chi = circuit.Chi
	circuit.doryUniform.C_Plus = circuit.C_Plus
	circuit.doryUniform.C_Minus = circuit.C_Minus
	circuit.doryUniform.D1_L = circuit.D1_L
	circuit.doryUniform.D1_R = circuit.D1_R
	circuit.doryUniform.D2_L = circuit.D2_L
	circuit.doryUniform.D2_R = circuit.D2_R
	circuit.doryUniform.Delta1_L = circuit.Delta1_L
	circuit.doryUniform.Delta1_R = circuit.Delta1_R
	circuit.doryUniform.Delta2_L = circuit.Delta2_L
	circuit.doryUniform.Delta2_R = circuit.Delta2_R

	circuit.doryUniform.E1_Beta = circuit.E1_Beta
	circuit.doryUniform.E1_PLUS = circuit.E1_PLUS
	circuit.doryUniform.E1_MINUS = circuit.E1_MINUS
	circuit.doryUniform.E2_Beta = circuit.E2_Beta
	circuit.doryUniform.E2_PLUS = circuit.E2_PLUS
	circuit.doryUniform.E2_MINUS = circuit.E2_MINUS

	circuit.doryUniform.doryverifierstep = &DoryVerifierStep{}

	// generate witness for DoryVerifierStep
	doryWitness := circuit.doryUniform.GenerateWitness(constraints[0])
	witness = append(witness, doryWitness...)

	// MultiMul for G1
	circuit.g1MultiMul = &uniform.G1MultiMul{
		Alpha:              circuit.Alpha,
		Beta:               circuit.Beta,
		D:                  circuit.D,
		E1_Beta:            circuit.E1_Beta,
		E1_Plus:            circuit.E1_PLUS,
		Alpha_Inv_E1_Minus: circuit.Alpha_Inv_E1_Minus,
		Gamma1:             circuit.Gamma1,
		Step:               &uniform.G1MulStep{},
	}

	g1MultiMulWitness := circuit.g1MultiMul.GenerateWitness(constraints[1])

	witness = append(witness, g1MultiMulWitness...)

	// MultiMul for G2
	circuit.g2MultiMul = &uniform.G2MultiMul{
		Alpha:              circuit.Alpha,
		Beta:               circuit.Beta,
		D:                  circuit.D,
		E2_Beta:            circuit.E2_Beta,
		E2_Plus:            circuit.E2_PLUS,
		Alpha_Inv_E2_Minus: circuit.Alpha_Inv_E2_Minus,
		DInvGamma2:         circuit.dInvTimes_Gamma2,
		Gamma2Out:          circuit.Gamma2,

		Step: &uniform.G2MulStep{},
	}

	g2MultiMulWitness := circuit.g2MultiMul.GenerateWitness(constraints[2])
	witness = append(witness, g2MultiMulWitness...)

	circuit.finalstep = &DoryVerifierFinalStepUniform{
		C:  circuit.doryUniform.doryverifierstep.C,
		D1: circuit.doryUniform.doryverifierstep.D1,
		D2: circuit.doryUniform.doryverifierstep.D2,
		E1: circuit.doryUniform.doryverifierstep.E1,
		E2: circuit.doryUniform.doryverifierstep.E2,
		Chi:              circuit.Chi[circuit.n-1],
		Gamma1:           circuit.Gamma1,
		D_times_Gamma1:   circuit.d_times_Gamma1,
		Gamma2:           circuit.Gamma2,
		DInvTimes_Gamma2: circuit.dInvTimes_Gamma2,
		V1:               circuit.V1,
		V2:               circuit.V2,

		D:     circuit.D,
		S:     circuit.S,
		R:     circuit.R,
		Alpha: circuit.Alpha,
		Step: &DoryVerifierFinalStep{
			D: circuit.D,
			S: circuit.S,
			R: circuit.R,
		},
	}

	finalStepWitness := circuit.finalstep.GenerateWitness(constraints[3])
	witness = append(witness, finalStepWitness...)

	return witness
}

func (circuit *DoryPieceWiseUniform) GetConstraints() uniform.PiecewiseUniformR1CS {

	return uniform.PiecewiseUniformR1CS{
		UniformR1CSes: []uniform.UniformR1CS{
			circuit.doryUniform.GetConstraints(),
			circuit.g1MultiMul.GetConstraints(),
			circuit.g2MultiMul.GetConstraints(),
			circuit.finalstep.GetConstraints(),
		},
	}
}
