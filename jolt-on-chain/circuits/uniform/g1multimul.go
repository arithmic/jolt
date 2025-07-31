package uniform

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/arithmic/gnark/constraint"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/utils"
	"github.com/consensys/gnark-crypto/ecc"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type G1MultiMul struct {
	Alpha []frontend.Variable `gnark:",public"`
	Beta  []frontend.Variable `gnark:",public"`
	D     frontend.Variable   `gnark:",public"`

	E1_Beta []groups.G1Projective

	E1_Plus []groups.G1Projective

	Alpha_Inv_E1_Minus []groups.G1Projective

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

	out_len := len(g1MultiMul.Alpha)

	var accBit frontend.Variable = 0

	var identity groups.G1Projective = groups.G1Projective{
		X: frontend.Variable(0),
		Y: frontend.Variable(1),
		Z: frontend.Variable(0),
	}

	var acc groups.G1Projective

	for j := 0; j < out_len; j++ {
		acc = identity
		accBit = 0

		exp_bn254_fr, _ := utils.FrontendVariableToBN254FrElement(g1MultiMul.Beta[j])
		var exp_bn254_fr_bigint big.Int
		exp_bn254_fr.BigInt(&exp_bn254_fr_bigint)

		// #1: beta * E1_Beta
		for i := 0; i < 128; i++ {
			g1MultiMul.Step.Acc = acc
			g1MultiMul.Step.Base = g1MultiMul.E1_Beta[j]

			g1MultiMul.Step.Bit = exp_bn254_fr_bigint.Bit(127 - i)
			g1MultiMul.Step.AccBit = accBit

			g1MultiMul.Step.Hint()
			witnessStep := g1MultiMul.Step.GenerateWitness(cs)
			witness = append(witness, witnessStep...)

			acc = g1MultiMul.Step.Out
			accBit = g1MultiMul.Step.BitOut
		}
	}

	for j := 0; j < out_len; j++ {
		acc = identity
		accBit = 0

		exp_bn254_fr, _ := utils.FrontendVariableToBN254FrElement(g1MultiMul.Alpha[j])
		var exp_bn254_fr_bigint big.Int
		exp_bn254_fr.BigInt(&exp_bn254_fr_bigint)

		// #2: alpha * E1_Plus
		for i := 0; i < 128; i++ {
			g1MultiMul.Step.Acc = acc
			g1MultiMul.Step.Base = g1MultiMul.E1_Plus[j]
			g1MultiMul.Step.Bit = exp_bn254_fr_bigint.Bit(127 - i)
			g1MultiMul.Step.AccBit = accBit

			g1MultiMul.Step.Hint()

			witnessStep := g1MultiMul.Step.GenerateWitness(cs)
			witness = append(witness, witnessStep...)

			acc = g1MultiMul.Step.Out
			accBit = g1MultiMul.Step.BitOut
		}
	}

	for j := 0; j < out_len; j++ {
		acc = identity
		accBit = 0

		exp_bn254_fr, _ := utils.FrontendVariableToBN254FrElement(g1MultiMul.Alpha[j])
		var exp_bn254_fr_bigint big.Int
		exp_bn254_fr.BigInt(&exp_bn254_fr_bigint)

		// 	#3: alpha * Alpha_Inv_E1_Minus
		for i := 0; i < 128; i++ {
			g1MultiMul.Step.Acc = acc
			g1MultiMul.Step.Base = g1MultiMul.Alpha_Inv_E1_Minus[j]
			g1MultiMul.Step.Bit = exp_bn254_fr_bigint.Bit(127 - i)
			g1MultiMul.Step.AccBit = accBit

			g1MultiMul.Step.Hint()

			witnessStep := g1MultiMul.Step.GenerateWitness(cs)
			witness = append(witness, witnessStep...)

			acc = g1MultiMul.Step.Out
			accBit = g1MultiMul.Step.BitOut
		}
	}

	acc = identity

	accBit = 0

	exp_bn254_fr, _ := utils.FrontendVariableToBN254FrElement(g1MultiMul.D)
	var exp_bn254_fr_bigint big.Int
	exp_bn254_fr.BigInt(&exp_bn254_fr_bigint)

	// 	#4: d * gamma1
	for i := 0; i < 128; i++ {
		g1MultiMul.Step.Acc = acc
		g1MultiMul.Step.Base = g1MultiMul.Gamma1
		g1MultiMul.Step.Bit = exp_bn254_fr_bigint.Bit(127 - i)
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

func (g1MultiMul *G1MultiMul) GetConstraints() UniformR1CS {
	var constraints []Constraint
	var aCount, bCount, cCount int

	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, g1MultiMul.Step)
	if err != nil {
		fmt.Println("err in compilation is ", err)
	}

	nR1CS, ok := r1cs.(constraint.R1CS)
	if !ok {
		return UniformR1CS{
			Constraints: constraints,
			ACount:      0,
			BCount:      0,
			CCount:      0,
			NumSteps:    0}
	}

	cs := nR1CS.GetR1Cs()
	for _, r1c := range cs {
		singular := Constraint{
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

	return UniformR1CS{
		Constraints: constraints,
		ACount:      uint32(aCount),
		BCount:      uint32(bCount),
		CCount:      uint32(cCount),
		NumSteps:    uint32((128) * (3*len(g1MultiMul.Alpha) + 1)),
	}
}
