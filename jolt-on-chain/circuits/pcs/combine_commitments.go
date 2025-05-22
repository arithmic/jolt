package pcs

import (
	"fmt"
	"github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/field_tower"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/uniform"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
	"strconv"
)

type gtExpUniformCircuit struct {
	In  field_tower.Fp12
	Acc field_tower.Fp12
	Bit frontend.Variable
	Out field_tower.Fp12 `gnark:",public"`

	in  bn254.E12
	acc bn254.E12
	bit uint
	out bn254.E12
}

func (circuit *gtExpUniformCircuit) Define(api frontend.API) error {
	gtAPI := field_tower.NewExt12(api)
	square := gtAPI.Square(&circuit.Acc)
	squareMul := gtAPI.Mul(square, &circuit.In)
	expectedOut := gtAPI.Select(circuit.Bit, squareMul, square)
	gtAPI.AssertIsEqual(&circuit.Out, expectedOut)
	return nil
}

func (circuit *gtExpUniformCircuit) Hint() {
	var square bn254.E12
	square = *square.Square(&circuit.acc)

	if circuit.bit == 1 {
		circuit.out = *(&circuit.out).Mul(&circuit.in, &square)
	} else {
		circuit.out = square
	}
}

func (circuit *gtExpUniformCircuit) Compile() *constraint.ConstraintSystem {
	circuitR1CS, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("err in compilation is ", err)
	}
	return &circuitR1CS
}

func (circuit *gtExpUniformCircuit) GenerateWitness(circuits []*gtExpUniformCircuit, r1cs *constraint.ConstraintSystem, _ uint32) fr.Vector {
	var witness fr.Vector

	circuits[0].Hint()
	circuits[0].Out = field_tower.FromE12(&circuits[0].out)
	for i := 1; i < len(circuits); i++ {
		circuits[i].Acc = field_tower.FromE12(&circuits[i-1].out)
		circuits[i].acc = circuits[i-1].out
		circuits[i].Hint()
		circuits[i].Out = field_tower.FromE12(&circuits[i].out)
	}

	for i := 0; i < 254; i++ {
		w, err := frontend.NewWitness(circuits[i], ecc.GRUMPKIN.ScalarField())
		if err != nil {
			fmt.Println("err in generate witness is ", err)
		}
		wSolved, _ := (*r1cs).Solve(w)

		witnessStep := wSolved.(*cs.R1CSSolution).W
		for _, elem := range witnessStep {
			witness = append(witness, fr.Element(elem))
		}
	}
	return witness
}
func (circuit *gtExpUniformCircuit) ExtractMatrices(circuitR1CS constraint.ConstraintSystem) ([]uniform.Constraint, int, int, int) {
	var outputConstraints []uniform.Constraint
	var aCount, bCount, cCount int

	// Assert to R1CS to get access to R1CS-specific methods
	nR1CS, ok := circuitR1CS.(constraint.R1CS)
	if !ok {
		return outputConstraints, 0, 0, 0 // or handle error
	}
	constraints := nR1CS.GetR1Cs()
	for _, r1c := range constraints {
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

		outputConstraints = append(outputConstraints, singular)
	}

	return outputConstraints, aCount, bCount, cCount
}
