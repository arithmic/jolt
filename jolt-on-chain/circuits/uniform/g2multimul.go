package uniform

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/arithmic/gnark/constraint"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/utils"
	"github.com/consensys/gnark-crypto/ecc"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type G2MultiMul struct {
	Alpha []frontend.Variable `gnark:",public"`
	Beta  []frontend.Variable `gnark:",public"`
	D     frontend.Variable   `gnark:",public"`

	E2_Beta []groups.G2Projective
	E2_Plus []groups.G2Projective

	Alpha_Inv_E2_Minus []groups.G2Projective

	Gamma2Out  groups.G2Projective
	DInvGamma2 groups.G2Projective

	Step *G2MulStep
}

func (g2MultiMul *G2MultiMul) CreateStepCircuit() constraint.ConstraintSystem {

	cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, g2MultiMul.Step)
	if err != nil {
		panic(err)
	}
	return cs
}

func (g2MultiMul *G2MultiMul) GenerateWitness(cs constraint.ConstraintSystem) grumpkin_fr.Vector {
	var witness grumpkin_fr.Vector
	out_len := len(g2MultiMul.Alpha)

	var accBit frontend.Variable = 0

	identity := groups.G2Projective{
		X: field_tower.Fp2{
			A0: frontend.Variable(0),
			A1: frontend.Variable(0),
		},
		Y: field_tower.Fp2{
			A0: frontend.Variable(1),
			A1: frontend.Variable(0),
		},
		Z: field_tower.Fp2{
			A0: frontend.Variable(0),
			A1: frontend.Variable(0),
		},
	}

	var acc groups.G2Projective
	for j := 0; j < out_len; j++ {
		acc = identity
		accBit = 0

		exp_bn254_fr, _ := utils.FrontendVariableToBN254FrElement(g2MultiMul.Beta[j])
		var exp_bn254_fr_bigint big.Int
		exp_bn254_fr.BigInt(&exp_bn254_fr_bigint)

		// #1: beta * E2_Beta
		for i := 0; i < 128; i++ {
			g2MultiMul.Step.Acc = acc
			g2MultiMul.Step.Base = g2MultiMul.E2_Beta[j]
			g2MultiMul.Step.Bit = exp_bn254_fr_bigint.Bit(127 - i)
			g2MultiMul.Step.AccBit = accBit

			g2MultiMul.Step.Hint()
			witnessStep := g2MultiMul.Step.GenerateWitness(cs)
			witness = append(witness, witnessStep...)

			acc = g2MultiMul.Step.Out
			accBit = g2MultiMul.Step.BitOut
		}
	}

	for j := 0; j < out_len; j++ {
		acc = identity
		accBit = 0

		exp_bn254_fr, _ := utils.FrontendVariableToBN254FrElement(g2MultiMul.Alpha[j])
		var exp_bn254_fr_bigint big.Int
		exp_bn254_fr.BigInt(&exp_bn254_fr_bigint)

		// #2: alpha * E2_Plus
		for i := 0; i < 128; i++ {
			g2MultiMul.Step.Acc = acc
			g2MultiMul.Step.Base = g2MultiMul.E2_Plus[j]
			g2MultiMul.Step.Bit = exp_bn254_fr_bigint.Bit(127 - i)
			g2MultiMul.Step.AccBit = accBit

			g2MultiMul.Step.Hint()
			witnessStep := g2MultiMul.Step.GenerateWitness(cs)
			witness = append(witness, witnessStep...)

			acc = g2MultiMul.Step.Out
			accBit = g2MultiMul.Step.BitOut
		}
	}

	for j := 0; j < out_len; j++ {
		acc = identity
		accBit = 0

		exp_bn254_fr, _ := utils.FrontendVariableToBN254FrElement(g2MultiMul.Alpha[j])
		var exp_bn254_fr_bigint big.Int
		exp_bn254_fr.BigInt(&exp_bn254_fr_bigint)

		// #3: alpha * Alpha_Inv_E2_Minus
		for i := 0; i < 128; i++ {
			g2MultiMul.Step.Acc = acc
			g2MultiMul.Step.Base = g2MultiMul.Alpha_Inv_E2_Minus[j]
			g2MultiMul.Step.Bit = exp_bn254_fr_bigint.Bit(127 - i)
			g2MultiMul.Step.AccBit = accBit

			g2MultiMul.Step.Hint()
			witnessStep := g2MultiMul.Step.GenerateWitness(cs)
			witness = append(witness, witnessStep...)

			acc = g2MultiMul.Step.Out
			accBit = g2MultiMul.Step.BitOut
		}
	}

	exp_bn254_fr, _ := utils.FrontendVariableToBN254FrElement(g2MultiMul.D)
	var exp_bn254_fr_bigint big.Int
	exp_bn254_fr.BigInt(&exp_bn254_fr_bigint)

	acc = identity
	accBit = 0
	// #4: d * dInvGamma2
	for i := 0; i < 128; i++ {
		g2MultiMul.Step.Acc = acc
		g2MultiMul.Step.Base = g2MultiMul.DInvGamma2
		g2MultiMul.Step.Bit = exp_bn254_fr_bigint.Bit(127 - i)
		g2MultiMul.Step.AccBit = accBit

		g2MultiMul.Step.Hint()
		witnessStep := g2MultiMul.Step.GenerateWitness(cs)
		witness = append(witness, witnessStep...)

		acc = g2MultiMul.Step.Out
		accBit = g2MultiMul.Step.BitOut
	}

	return witness
}

func (g2MultiMul *G2MultiMul) GetConstraints() UniformR1CS {
	var constraints []Constraint
	var aCount, bCount, cCount int

	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, g2MultiMul.Step)
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
		NumSteps:    uint32((128) * (3*len(g2MultiMul.Alpha) + 1)),
	}
}
