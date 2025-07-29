package uniform

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

	// bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

// ------------------------
// One step of G2 scalar mul
// ------------------------

type G2MulStep struct {
	// Inputs
	Base groups.G2Projective
	Acc  groups.G2Projective

	Bit    frontend.Variable
	AccBit frontend.Variable
	BitOut frontend.Variable

	// Output
	Out groups.G2Projective
}

// Constraints: Out = Double(Acc) + Base*Bit
// BitOut = 2*AccBit + Bit
func (step *G2MulStep) Define(api frontend.API) error {
	api.AssertIsBoolean(step.Bit)

	g := groups.New(api)

	double := g.Double(&step.Acc)
	added := g.Add(double, &step.Base)
	out := g.Select(step.Bit, added, double)

	g.AssertIsEqual(&step.Out, out)

	api.AssertIsEqual(step.BitOut, api.Add(api.Mul(step.AccBit, 2), step.Bit))

	return nil
}

// Native hint for computing Out + BitOut
func (step *G2MulStep) Hint() {
	accAffine := groups.To_Bn254G2Affine(step.Acc)
	baseAffine := groups.To_Bn254G2Affine(step.Base)

	var double bn254.G2Affine
	double.Double(&accAffine)

	// Parse Bit to int
	bitFr, _ := utils.FrontendVariableToFrElement(step.Bit)
	var bitInt big.Int
	bitFr.BigInt(&bitInt)

	// Compute Out
	var out bn254.G2Affine
	if bitInt.Int64() == 1 {
		out.Add(&double, &baseAffine)
	} else {
		out = double
	}
	step.Out = groups.FromBNG2Affine(&out)

	// Compute BitOut = 2*AccBit + Bit
	accBitFr, _ := utils.FrontendVariableToFrElement(step.AccBit)
	var accBitInt big.Int
	accBitFr.BigInt(&accBitInt)

	bitOut := new(big.Int).Add(
		new(big.Int).Lsh(&accBitInt, 1), // 2*AccBit
		&bitInt,
	)
	step.BitOut = bitOut
}

// Generate witness for one step
func (circuit *G2MulStep) GenerateWitness(constraints constraint.ConstraintSystem) grumpkin_fr.Vector {
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

type G2Mul struct {
	Base groups.G2Projective
	Exp  frontend.Variable // 128 bits

	Step *G2MulStep
}

// Compile single step
func (gmul *G2Mul) CreateStepCircuit() constraint.ConstraintSystem {
	gmul.Step = &G2MulStep{
		Base: gmul.Base,
	}

	cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, gmul.Step)
	if err != nil {
		panic(err)
	}
	return cs
}

// Run full scalar mul by stepping through all 128 bits
func (gmul *G2Mul) GenerateWitness(cs constraint.ConstraintSystem) grumpkin_fr.Vector {
	acc := groups.G2Projective{
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
	var bitAcc any = big.NewInt(0)

	var witness grumpkin_fr.Vector

	exp_bn254_fr, _ := utils.FrontendVariableToBN254FrElement(gmul.Exp)
	var exp_bn254_fr_bigint big.Int
	exp_bn254_fr.BigInt(&exp_bn254_fr_bigint)

	// MSB -> LSB
	for i := 0; i < 128; i++ {
		bit := exp_bn254_fr_bigint.Bit(127 - i)

		// Fill step inputs
		gmul.Step.Acc = acc
		gmul.Step.Base = gmul.Base
		gmul.Step.Bit = bit
		gmul.Step.AccBit = bitAcc

		// Native step hint
		gmul.Step.Hint()

		// Solve for this step
		witnessStep := gmul.Step.GenerateWitness(cs)

		// Collect
		witness = append(witness, witnessStep...)

		// Next step input state
		acc = gmul.Step.Out
		bitAcc = gmul.Step.BitOut
	}

	return witness
}
