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
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

func RandomG1Affine() bn254.G1Affine {
	_, _, gen, _ := bn254.Generators()
	mod := bn254.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bn254.G1Affine
	p.ScalarMultiplication(&gen, s1)

	return p
}

type G1DoubleCircuit struct {
	A, C G1Projective
}

func (circuit *G1DoubleCircuit) Define(api frontend.API) error {
	g := &G1API{api: api}
	result := g.Double(&circuit.A)
	g.AssertIsEqual(result, &circuit.C)
	return nil
}

func TestCircuitG1Double(t *testing.T) {

	var circuit G1DoubleCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of G1DoubleCircuit", r1cs.GetNbConstraints())

	var a, c bn254.G1Affine

	a = RandomG1Affine()
	c.Double(&a)

	assignment := &G1DoubleCircuit{
		A: FromG1Affine(&a),
		C: FromG1Affine(&c),
	}

	// Generate witness
	start_witness := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
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

type G1AddCircuit struct {
	A, B, C G1Projective
}

func (circuit *G1AddCircuit) Define(api frontend.API) error {
	g := G1API{api: api}
	result := g.Add(&circuit.A, &circuit.B)
	g.AssertIsEqual(result, &circuit.C)
	return nil
}

func TestCircuitG1Add(t *testing.T) {

	var circuit G1AddCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of G1AddCircuit", r1cs.GetNbConstraints())

	var a, b, c bn254.G1Affine
	a = RandomG1Affine()
	b = RandomG1Affine()
	c.Add(&a, &b)

	assignment := &G1AddCircuit{
		A: FromG1Affine(&a),
		B: FromG1Affine(&b),
		C: FromG1Affine(&c),
	}

	// Generate witness
	start_witness := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
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

type G1ScalarMulCircuit struct {
	A, C G1Projective
	Exp  frontend.Variable
}

func (circuit *G1ScalarMulCircuit) Define(api frontend.API) error {
	g := &G1API{api: api}
	result := g.ScalarMul(&circuit.A, &circuit.Exp)
	g.AssertIsEqual(result, &circuit.C)
	return nil
}

func TestCircuitG1ScalarMul(t *testing.T) {

	var circuit G1ScalarMulCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of G1ScalarMulCircuit", r1cs.GetNbConstraints())

	var a, c bn254.G1Affine
	a = RandomG1Affine()

	b_big, _ := rand.Int(rand.Reader, fp.Modulus())

	var b1 fr.Element
	b1.SetBigInt(b_big)

	c.ScalarMultiplication(&a, b_big)

	assignment := &G1ScalarMulCircuit{
		A:   FromG1Affine(&a),
		Exp: b1,
		C:   FromG1Affine(&c),
	}

	// Generate witness
	start_witness := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
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
