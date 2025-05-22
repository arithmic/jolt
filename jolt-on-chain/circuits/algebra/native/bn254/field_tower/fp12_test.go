package field_tower

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254_fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type Fp12AddCircuit struct {
	A, B Fp12
	C    Fp12 `gnark:",public"`
}

func (circuit *Fp12AddCircuit) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := *e.Add(&circuit.A, &circuit.B)
	api.Println("expected:", expected)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp12Add(t *testing.T) {
	// Define the circuit

	var circuit Fp12AddCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp12Add", r1cs.GetNbConstraints())
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	assignment := &Fp12AddCircuit{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
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
	_, _ = r1cs.Solve(witness)
	duration_witness := time.Since(start_witness)
	fmt.Printf("Witness generated in: %s\n", duration_witness)

}

type Fp12ConjugateCircuit struct {
	A Fp12
	C Fp12 `gnark:",public"`
}

func (circuit *Fp12ConjugateCircuit) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := *e.Conjugate(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp12Conjugate(t *testing.T) {
	// Define the circuit
	var circuit Fp12ConjugateCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp12Conjugate", r1cs.GetNbConstraints())
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	assignment := &Fp12ConjugateCircuit{
		A: FromE12(&a),
		C: FromE12(&c),
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

type Fp12MulCircuit struct {
	A, B Fp12
	C    Fp12 `gnark:",public"`
}

func (circuit *Fp12MulCircuit) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := *e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp12Mul(t *testing.T) {
	// Define the circuit
	var circuit Fp12MulCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp12Mul", r1cs.GetNbConstraints())
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	assignment := &Fp12MulCircuit{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
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

type Fp12SquareCircuit struct {
	A Fp12
	C Fp12 `gnark:",public"`
}

func (circuit *Fp12SquareCircuit) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := *e.Square(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp12Square(t *testing.T) {
	// Define the circuit

	var circuit Fp12SquareCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp12Square", r1cs.GetNbConstraints())
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Square(&a)

	assignment := &Fp12SquareCircuit{
		A: FromE12(&a),
		C: FromE12(&c),
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

type Fp12InverseCircuit struct {
	A Fp12
	C Fp12 `gnark:",public"`
}

func (circuit *Fp12InverseCircuit) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := *e.Inverse(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp12Inverse(t *testing.T) {
	// Define the circuit

	var circuit Fp12InverseCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp12Inverse", r1cs.GetNbConstraints())
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Inverse(&a)

	assignment := &Fp12InverseCircuit{
		A: FromE12(&a),
		C: FromE12(&c),
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

type Fp12Exp struct {
	A Fp12
	B frontend.Variable
	C Fp12 `gnark:",public"`
}

func (circuit *Fp12Exp) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Exp(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitFp12Exp(t *testing.T) {
	// Define the circuit
	var circuit Fp12Exp
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp12Exp", r1cs.GetNbConstraints())
	var a, c bn254.E12
	_, _ = a.SetRandom()
	var b bn254_fp.Element
	_, _ = b.SetRandom()
	var bBigInt big.Int
	b.BigInt(&bBigInt)

	c.Exp(a, &bBigInt)
	assignment := &Fp12Exp{
		A: FromE12(&a),
		B: grumpkin_fr.Element(b),
		C: FromE12(&c),
	}

	// Generate witness
	start_witness := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	_, err = r1cs.Solve(witness)
	if err != nil {
		fmt.Println("Error solving the r1cs", err)
		return
	}
	duration_witness := time.Since(start_witness)
	fmt.Printf("Witness generated in: %s\n", duration_witness)

}
