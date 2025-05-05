package groups

import (
	"crypto/rand"
	"fmt"

	"testing"
	"time"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type G2AddCircuit struct {
	A, B, C G2Projective
}

func (circuit *G2AddCircuit) Define(api frontend.API) error {
	e := New(api)

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
	var circuit G2AddCircuit
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

	assignment := G2AddCircuit{
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

type G2MulCircuit struct {
	A, C G2Projective
	In2  frontend.Variable
}

func (circuit *G2MulCircuit) Define(api frontend.API) error {
	e := New(api)

	expected := e.Mul(&circuit.A, &circuit.In2)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestCircuitG2Mul(t *testing.T) {
	var circuit G2MulCircuit
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of G2Mul", r1cs.GetNbConstraints())

	_, in1 := randomG1G2Affines()

	var c bn254.G2Affine

	bBigInt, _ := rand.Int(rand.Reader, bn254_fr.Modulus())

	var b1 grumpkin_fr.Element
	b1.SetBigInt(bBigInt)

	c.ScalarMultiplication(&in1, bBigInt)

	assignment := G2MulCircuit{
		A:   FromBNG2Affine(&in1),
		In2: b1,
		C:   FromBNG2Affine(&c),
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

type G2DoubleCircuit struct {
	A, B G2Projective
}

func (circuit *G2DoubleCircuit) Define(api frontend.API) error {
	e := New(api)
	expected := e.Double(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestCircuitG2Double(t *testing.T) {
	var circuit G2DoubleCircuit
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of G2Double", r1cs.GetNbConstraints())

	_, in1 := randomG1G2Affines()
	var res bn254.G2Affine
	res.Double(&in1)

	assignment := G2DoubleCircuit{
		A: FromBNG2Affine(&in1),
		B: FromBNG2Affine(&res),
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

type G2toProjectiveCircuit struct {
	A G2Affine
	B G2Projective
}

func (circuit *G2toProjectiveCircuit) Define(api frontend.API) error {
	e := New(api)
	expected := e.ToProjective(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

// To test this one for identity element, we have to change A0 to 0 instead of 1.
// and uncomment the line next to randomG1G2Affines.
func TestCircuitG2toProjective(t *testing.T) {
	var circuit G2toProjectiveCircuit
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of G2toProjectiveCircuit", r1cs.GetNbConstraints())

	_, in1 := randomG1G2Affines()
	// in1 = *in1.ScalarMultiplication(&in1, bn254_fr.Modulus())

	assignment := G2toProjectiveCircuit{
		A: G2AffineFromBNG2Affine(&in1),
		B: FromBNG2Affine(&in1),
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
