package g1ops

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type G2Add struct {
	A, B, C G2Affine
}

func (circuit *G2Add) Define(api frontend.API) error {
	e := NewG2(api)
	_ = e.Add(&circuit.A, &circuit.B)
	// expected.X = api.Div(expected.X, expected.Z)
	// expected.Y = api.Div(expected.Y, expected.Z)
	// expected.Z = fr.One()
	// g.AssertIsEqual(expected, &circuit.C)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func randomG1G2Affines() (bn254.G1Affine, bn254.G2Affine) {
	_, _, G1AffGen, G2AffGen := bn254.Generators()
	mod := bn254.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bn254.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bn254.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

func TestCircuitG2Add(t *testing.T) {
	var circuit G2Add
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of G2Add", r1cs.GetNbConstraints())

	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bn254.G2Affine
	res.Add(&in1, &in2)

	assignment := G2Add{
		A: FromBNG2Affine(&in1),
		B: FromBNG2Affine(&in2),
		C: FromBNG2Affine(&res),
	}

	// Generate witness
	start_witness := time.Now()
	witness, err := frontend.NewWitness(&assignment, ecc.GRUMPKIN.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	_, err_1 := r1cs.Solve(witness)
	if err_1 != nil {
		fmt.Println("Error solving the r1cs", err_1)
		return
	}
	duration_witness := time.Since(start_witness)
	fmt.Printf("Witness generated in: %s\n", duration_witness)
}
