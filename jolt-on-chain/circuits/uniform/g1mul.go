package uniform

import (
	"fmt"
	"math/big"

	"github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

// ------------------------
// One scalar mul step
// ------------------------

type G1MulStep struct {
	// Inputs
	Base groups.G1Projective
	Acc  groups.G1Projective

	Bit    frontend.Variable
	AccBit frontend.Variable
	BitOut frontend.Variable

	// Output
	Out groups.G1Projective
}

// Constraints: Out = Double(Acc) + Base*Bit
// BitOut = 2*AccBit + Bit
func (circuit *G1MulStep) Define(api frontend.API) error {
	api.AssertIsBoolean(circuit.Bit)
	g := groups.NewG1API(api)
	// Double the accumulator
	double := g.Double(&circuit.Acc)
	// Conditional add base
	added := g.Add(double, &circuit.Base)

	// Select output based on the bit
	out := g.Select(circuit.Bit, added, double)

	g.AssertIsEqual(&circuit.Out, out)
	api.AssertIsEqual(circuit.BitOut, api.Add(api.Mul(circuit.AccBit, 2), circuit.Bit))

	return nil
}

// Native hint for computing Out + BitOut
func (step *G1MulStep) Hint() {
	accAffine := groups.To_Bn254G1Affine(step.Acc)
	baseAffine := groups.To_Bn254G1Affine(step.Base)

	var double bn254.G1Affine
	double.Double(&accAffine)

	// Parse Bit to int
	bitFr, _ := utils.FrontendVariableToFrElement(step.Bit)
	var bitInt big.Int
	bitFr.BigInt(&bitInt)

	// Compute Out
	var out bn254.G1Affine
	if bitInt.Int64() == 1 {
		out.Add(&double, &baseAffine)
	} else {
		out = double
	}
	step.Out = groups.FromG1Affine(&out)

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

// Generate one step's witness
func (circuit *G1MulStep) GenerateWitness(constraints constraint.ConstraintSystem) grumpkin_fr.Vector {
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

type G1Mul struct {
	Base groups.G1Projective
	Exp  frontend.Variable // 128 bits

	Step *G1MulStep
}

// Compile one step circuit
func (gmul *G1Mul) CreateStepCircuit() constraint.ConstraintSystem {
	gmul.Step = &G1MulStep{
		Base: gmul.Base,
	}

	cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, gmul.Step)
	if err != nil {
		panic(err)
	}
	return cs
}

// Run full scalar mul by stepping through all 128 bits
func (gmul *G1Mul) GenerateWitness(cs constraint.ConstraintSystem) grumpkin_fr.Vector {
	acc := groups.G1Projective{
		X: frontend.Variable(0),
		Y: frontend.Variable(1),
		Z: frontend.Variable(0),
	}

	var bitAcc any = big.NewInt(0)

	var witness grumpkin_fr.Vector

	exp_bn254_fr, _ := utils.FrontendVariableToBN254FrElement(gmul.Exp)
	var exp_bn254_fr_bigint big.Int
	exp_bn254_fr.BigInt(&exp_bn254_fr_bigint)

	for i := 0; i < 128; i++ {
		bit := exp_bn254_fr_bigint.Bit(127 - i)
		//
		// Setup step
		gmul.Step.Acc = acc
		gmul.Step.Base = gmul.Base
		gmul.Step.Bit = bit
		gmul.Step.AccBit = bitAcc

		// Native step hint
		gmul.Step.Hint()

		// Solve circuit for this step
		witnessStep := gmul.Step.GenerateWitness(cs)

		// Append step to total witness
		witness = append(witness, witnessStep...)

		// Update state for next step
		acc = gmul.Step.Out
		bitAcc = gmul.Step.BitOut
	}

	return witness
}
