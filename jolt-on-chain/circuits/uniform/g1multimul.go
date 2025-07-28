package uniform

import (
	"math/big"

	"github.com/arithmic/gnark/constraint"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"
	"github.com/consensys/gnark-crypto/ecc"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type G1MultiMul struct {
	Alpha big.Int `gnark:",public"`
	Beta  big.Int `gnark:",public"`
	d     big.Int `gnark:",public"`

	E1_Beta groups.G1Projective

	E1_Plus groups.G1Projective

	Alpha_Inv_E1_Minus groups.G1Projective

	Gamma1 groups.G1Projective

	dGamma1Out groups.G1Projective

	Step *G1MulStep
}

func (g1MultiMul *G1MultiMul) CreateStepCircuit() constraint.ConstraintSystem {

	cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, g1MultiMul.Step)
	if err != nil {
		panic(err)
	}
	return cs
}

func (g1MultiMul *G1MultiMul) GenerateWitness(cs constraint.ConstraintSystem) grumpkin_fr.Vector {
	var witness grumpkin_fr.Vector

	var accBit frontend.Variable = 0

	var acc groups.G1Projective = groups.G1Projective{
		X: frontend.Variable(0),
		Y: frontend.Variable(1),
		Z: frontend.Variable(0),
	}

	// #1: beta * E1_Beta
	for i := 0; i < 128; i++ {
		g1MultiMul.Step.Acc = acc
		g1MultiMul.Step.Base = g1MultiMul.E1_Beta
		g1MultiMul.Step.Bit = g1MultiMul.Beta.Bit(127 - i)
		g1MultiMul.Step.AccBit = accBit

		g1MultiMul.Step.Hint()
		witnessStep := g1MultiMul.Step.GenerateWitness(cs)
		witness = append(witness, witnessStep...)

		acc = g1MultiMul.Step.Out
		accBit = g1MultiMul.Step.BitOut
	}

	acc = groups.G1Projective{
		X: frontend.Variable(0),
		Y: frontend.Variable(1),
		Z: frontend.Variable(0),
	}
	accBit = 0

	// #2: alpha * E1_Plus
	for i := 0; i < 128; i++ {
		g1MultiMul.Step.Acc = acc
		g1MultiMul.Step.Base = g1MultiMul.E1_Plus
		g1MultiMul.Step.Bit = g1MultiMul.Alpha.Bit(127 - i)
		g1MultiMul.Step.AccBit = accBit

		g1MultiMul.Step.Hint()

		witnessStep := g1MultiMul.Step.GenerateWitness(cs)
		witness = append(witness, witnessStep...)

		acc = g1MultiMul.Step.Out
		accBit = g1MultiMul.Step.BitOut
	}

	acc = groups.G1Projective{
		X: frontend.Variable(0),
		Y: frontend.Variable(1),
		Z: frontend.Variable(0),
	}
	accBit = 0

	// 	#3: alpha * Alpha_Inv_E1_Minus
	for i := 0; i < 128; i++ {
		g1MultiMul.Step.Acc = acc
		g1MultiMul.Step.Base = g1MultiMul.Alpha_Inv_E1_Minus
		g1MultiMul.Step.Bit = g1MultiMul.Alpha.Bit(127 - i)
		g1MultiMul.Step.AccBit = accBit

		g1MultiMul.Step.Hint()

		witnessStep := g1MultiMul.Step.GenerateWitness(cs)
		witness = append(witness, witnessStep...)

		acc = g1MultiMul.Step.Out
		accBit = g1MultiMul.Step.BitOut
	}

	acc = groups.G1Projective{
		X: frontend.Variable(0),
		Y: frontend.Variable(1),
		Z: frontend.Variable(0),
	}
	accBit = 0

	// 	#4: d * gamma1
	for i := 0; i < 128; i++ {
		g1MultiMul.Step.Acc = acc
		g1MultiMul.Step.Base = g1MultiMul.Gamma1
		g1MultiMul.Step.Bit = g1MultiMul.d.Bit(127 - i)
		g1MultiMul.Step.AccBit = accBit

		g1MultiMul.Step.Hint()

		witnessStep := g1MultiMul.Step.GenerateWitness(cs)
		witness = append(witness, witnessStep...)

		acc = g1MultiMul.Step.Out
		accBit = g1MultiMul.Step.BitOut
	}

	g1MultiMul.dGamma1Out = acc

	return witness
}
