package pcs

import (
	"github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/field_tower"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
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
	r1cs, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit)
	return &r1cs
}

func (dummyCircuit *gtExpUniformCircuit) GenerateWitness(circuits []*gtExpUniformCircuit, r1cs *constraint.ConstraintSystem, numSteps uint32) fr.Vector {
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
		w, _ := frontend.NewWitness(circuits[i], ecc.GRUMPKIN.ScalarField())

		wSolved, _ := (*r1cs).Solve(w)

		witnessStep := wSolved.(*cs.R1CSSolution).W
		for _, elem := range witnessStep {
			witness = append(witness, fr.Element(elem))
		}

	}

	return witness
}
