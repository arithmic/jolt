package field_tower

import (
	"fmt"
	"testing"
	"time"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type Fp6AddCircuit struct {
	A, B Fp6
	C    Fp6 `gnark:",public"`
}

func (circuit *Fp6AddCircuit) Define(api frontend.API) error {
	e := Ext6{e2: Ext2{api: api}}
	expected := *e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp6Add(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp6AddCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp6Add", r1cs.GetNbConstraints())
	var a, b, c bn254.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	assignment := &Fp6AddCircuit{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
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

type Fp6DoubleCircuit struct {
	A Fp6
	C Fp6 `gnark:",public"`
}

func (circuit *Fp6DoubleCircuit) Define(api frontend.API) error {
	e := Ext6{e2: Ext2{api: api}}
	expected := e.Double(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitFp6Double(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp6DoubleCircuit

	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp6DoubleCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E6
	_, _ = a.SetRandom()
	c.Double(&a)
	assignment := &Fp6DoubleCircuit{
		A: FromE6(&a),
		C: FromE6(&c),
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

type Fp6SubCircuit struct {
	A, B Fp6
	C    Fp6 `gnark:",public"`
}

func (circuit *Fp6SubCircuit) Define(api frontend.API) error {
	e := Ext6{e2: Ext2{api: api}}
	expected := *e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp6Sub(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp6SubCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp6Sub", r1cs.GetNbConstraints())
	var a, b, c bn254.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	assignment := &Fp6SubCircuit{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
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

type Fp6NegCircuit struct {
	A Fp6
	C Fp6 `gnark:",public"`
}

func (circuit *Fp6NegCircuit) Define(api frontend.API) error {
	e := Ext6{e2: Ext2{api: api}}
	expected := *e.Neg(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp6Neg(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp6NegCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp6Neg", r1cs.GetNbConstraints())
	var a, c bn254.E6
	_, _ = a.SetRandom()
	c.Neg(&a)

	assignment := &Fp6NegCircuit{
		A: FromE6(&a),
		C: FromE6(&c),
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

type Fp6MulCircuit struct {
	A, B Fp6
	C    Fp6 `gnark:",public"`
}

func (circuit *Fp6MulCircuit) Define(api frontend.API) error {
	e := Ext6{e2: Ext2{api: api}}
	expected := *e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp6Mul(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp6MulCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp6Mul", r1cs.GetNbConstraints())
	var a, b, c bn254.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	assignment := &Fp6MulCircuit{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
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

type Fp6SquareCircuit struct {
	A Fp6
	C Fp6 `gnark:",public"`
}

func (circuit *Fp6SquareCircuit) Define(api frontend.API) error {
	e := Ext6{e2: Ext2{api: api}}
	expected := *e.Square(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp6Square(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp6SquareCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp6Square", r1cs.GetNbConstraints())
	var a, c bn254.E6
	_, _ = a.SetRandom()
	c.Square(&a)

	assignment := &Fp6SquareCircuit{
		A: FromE6(&a),
		C: FromE6(&c),
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

type Fp6InverseCircuit struct {
	A Fp6
	C Fp6 `gnark:",public"`
}

func (circuit *Fp6InverseCircuit) Define(api frontend.API) error {
	e := Ext6{e2: Ext2{api: api}}
	expected := *e.Inverse(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp6Inverse(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp6InverseCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp6Inverse", r1cs.GetNbConstraints())
	var a, c bn254.E6
	_, _ = a.SetRandom()
	c.Inverse(&a)

	assignment := &Fp6InverseCircuit{
		A: FromE6(&a),
		C: FromE6(&c),
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

type Fp6MulByNonResidueCircuit struct {
	A Fp6
	C Fp6 `gnark:",public"`
}

func (circuit *Fp6MulByNonResidueCircuit) Define(api frontend.API) error {
	e := Ext6{e2: Ext2{api: api}}
	expected := *e.MulByNonResidue(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitFp6MulByNonResidue(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp6MulByNonResidueCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp6MulByNonResidue", r1cs.GetNbConstraints())
	var a, c bn254.E6
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	assignment := &Fp6MulByNonResidueCircuit{
		A: FromE6(&a),
		C: FromE6(&c),
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
