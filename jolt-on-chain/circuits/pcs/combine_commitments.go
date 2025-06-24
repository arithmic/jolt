package pcs

import (
	"fmt"

	"math/big"
	"strconv"

	"github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"

	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/uniform"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254Fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type gtExpStepCircuit struct {
	In  field_tower.Fp12
	Acc field_tower.Fp12
	Bit frontend.Variable
	Out field_tower.Fp12 `gnark:",public"`

	in  bn254.E12
	acc bn254.E12
	bit uint
	out bn254.E12
}

func (circuit *gtExpStepCircuit) Define(api frontend.API) error {
	gtAPI := field_tower.NewExt12(api)
	square := gtAPI.Square(&circuit.Acc)
	squareMul := gtAPI.Mul(square, &circuit.In)
	expectedOut := gtAPI.Select(circuit.Bit, squareMul, square)
	gtAPI.AssertIsEqual(&circuit.Out, expectedOut)
	return nil
}

func (circuit *gtExpStepCircuit) Hint() {
	var square bn254.E12
	square = *square.Square(&circuit.acc)

	if circuit.bit == 1 {
		circuit.out = *(&circuit.out).Mul(&circuit.in, &square)
	} else {
		circuit.out = square
	}

	// fmt.Println("out is ", circuit.out)

	circuit.Out = field_tower.FromE12(&circuit.out)
}

type gtExpUniformCircuit struct {
	g   bn254.E12
	exp bn254Fp.Element
	res bn254.E12 `gnark:",public"`

	dummyCircuit *gtExpStepCircuit
	gtExpSteps   []*gtExpStepCircuit
}

func (circuit *gtExpUniformCircuit) Compile() *constraint.ConstraintSystem {

	circuitR1CS, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit.dummyCircuit)
	if err != nil {
		fmt.Println("err in compilation is ", err)
	}
	return &circuitR1CS
}

func (circuit *gtExpUniformCircuit) CreateStepCircuits() {
	circuit.gtExpSteps = make([]*gtExpStepCircuit, 254)

	var ext field_tower.Ext12
	var e bn254.E12
	var frBigInt big.Int
	circuit.exp.BigInt(&frBigInt)

	bit := frBigInt.Bit(253)
	circuit.gtExpSteps[0] = &gtExpStepCircuit{
		In:  field_tower.FromE12(&circuit.g),
		Acc: *ext.One(),
		Bit: bit,
		Out: *ext.One(),

		in:  circuit.g,
		acc: *e.SetOne(),
		bit: bit,
		out: *e.SetOne(),
	}

	circuit.gtExpSteps[0].Hint()

	for i := 1; i < 254; i++ {
		bit := frBigInt.Bit(253 - i)
		circuit.gtExpSteps[i] = &gtExpStepCircuit{
			In:  field_tower.FromE12(&circuit.g),
			Acc: circuit.gtExpSteps[i-1].Out,
			Bit: bit,
			Out: *ext.One(),

			in:  circuit.g,
			acc: circuit.gtExpSteps[i-1].out,
			bit: bit,
			out: *e.SetOne(),
		}
		circuit.gtExpSteps[i].Hint()
	}
}

func (circuit *gtExpUniformCircuit) GenerateWitness() fr.Vector {

	// TODO: Change this to 110 or 128 if we decide to use a random field element with fewer bits.
	if len(circuit.gtExpSteps) != 254 {
		panic("len of gtExpSteps should be 254.")
	}

	var witness fr.Vector

	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit.dummyCircuit)
	if err != nil {
		fmt.Println("err in compilation is ", err)
	}

	for i := 0; i < len(circuit.gtExpSteps); i++ {
		w, err := frontend.NewWitness(circuit.gtExpSteps[i], ecc.GRUMPKIN.ScalarField())
		if err != nil {
			fmt.Println("err in generate witness is ", err)
		}
		wSolved, _ := r1cs.Solve(w)

		witnessStep := wSolved.(*cs.R1CSSolution).W
		for _, elem := range witnessStep {
			witness = append(witness, fr.Element(elem))
		}
	}
	return witness
}

func (circuit *gtExpUniformCircuit) GetConstraints() uniform.UniformR1CS {
	var constraints []uniform.Constraint
	var aCount, bCount, cCount int

	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit.dummyCircuit)
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
		NumSteps:    uint32(len(circuit.gtExpSteps))}
}

// func (circuit *gtExpUniformCircuit) ExtractMatrices(circuitR1CS constraint.ConstraintSystem) ([]uniform.Constraint, int, int, int) {
// 	var outputConstraints []uniform.Constraint
// 	var aCount, bCount, cCount int

// 	// Assert to R1CS to get access to R1CS-specific methods
// 	nR1CS, ok := circuitR1CS.(constraint.R1CS)
// 	if !ok {
// 		return outputConstraints, 0, 0, 0 // or handle error
// 	}
// 	constraints := nR1CS.GetR1Cs()
// 	for _, r1c := range constraints {
// 		singular := uniform.Constraint{
// 			A: make(map[string]string),
// 			B: make(map[string]string),
// 			C: make(map[string]string),
// 		}

// 		for _, term := range r1c.L {
// 			val := nR1CS.CoeffToString(int(term.CID))
// 			col := strconv.FormatUint(uint64(term.VID), 10)
// 			singular.A[col] = val
// 			aCount++
// 		}
// 		for _, term := range r1c.R {
// 			val := nR1CS.CoeffToString(int(term.CID))
// 			col := strconv.FormatUint(uint64(term.VID), 10)
// 			singular.B[col] = val
// 			bCount++
// 		}
// 		for _, term := range r1c.O {
// 			val := nR1CS.CoeffToString(int(term.CID))
// 			col := strconv.FormatUint(uint64(term.VID), 10)
// 			singular.C[col] = val
// 			cCount++
// 		}

// 		outputConstraints = append(outputConstraints, singular)
// 	}

// 	return outputConstraints, aCount, bCount, cCount
// }
