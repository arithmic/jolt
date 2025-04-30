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

type Fp2AddCircuit struct {
	A, B Fp2
	C    Fp2 `gnark:",public"`
}

func (circuit *Fp2AddCircuit) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := *e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitAdd(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2AddCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2Add", r1cs.GetNbConstraints())
	var a, b, c bn254.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	assignment := &Fp2AddCircuit{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
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

type Fp2DoubleCircuit struct {
	A Fp2
	C Fp2 `gnark:",public"`
}

func (circuit *Fp2DoubleCircuit) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := e.Double(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitDouble(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2DoubleCircuit

	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2DoubleCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.Double(&a)
	assignment := &Fp2DoubleCircuit{
		A: FromE2(&a),
		C: FromE2(&c),
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

type Fp2SubCircuit struct {
	A, B Fp2
	C    Fp2 `gnark:",public"`
}

func (circuit *Fp2SubCircuit) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitSub(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2SubCircuit

	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2SubCircuit", r1cs.GetNbConstraints())
	var a, b, c bn254.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)
	assignment := &Fp2SubCircuit{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
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

type Fp2NegCircuit struct {
	A Fp2
	C Fp2 `gnark:",public"`
}

func (circuit *Fp2NegCircuit) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := *e.Neg(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitNeg(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2NegCircuit

	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2NegCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.Neg(&a)
	assignment := &Fp2NegCircuit{
		A: FromE2(&a),
		C: FromE2(&c),
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

type Fp2ConjugateCircuit struct {
	A Fp2
	C Fp2 `gnark:",public"`
}

func (circuit *Fp2ConjugateCircuit) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := e.Conjugate(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitConjugate(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2ConjugateCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2ConjugateCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.Conjugate(&a)
	assignment := &Fp2ConjugateCircuit{
		A: FromE2(&a),
		C: FromE2(&c),
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

type Fp2MulCircuit struct {
	A, B Fp2
	C    Fp2 `gnark:",public"`
}

func (circuit *Fp2MulCircuit) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := *e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitMul(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2MulCircuit

	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2MulCircuit", r1cs.GetNbConstraints())
	var a, b, c bn254.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)
	assignment := &Fp2MulCircuit{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
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

type Fp2SquareCircuit struct {
	A Fp2
	C Fp2 `gnark:",public"`
}

func (circuit *Fp2SquareCircuit) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := *e.Square(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestCircuitSquare(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2SquareCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2SquareCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.Square(&a)
	assignment := &Fp2SquareCircuit{
		A: FromE2(&a),
		C: FromE2(&c),
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

type Fp2InverseCircuit struct {
	A Fp2
	C Fp2 `gnark:",public"`
}

func (circuit *Fp2InverseCircuit) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitInverse(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2InverseCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2InverseCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.Inverse(&a)
	assignment := &Fp2InverseCircuit{
		A: FromE2(&a),
		C: FromE2(&c),
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

type Fp2MulByNonResidueCircuit struct {
	A Fp2
	C Fp2 `gnark:",public"`
}

func (circuit *Fp2MulByNonResidueCircuit) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := e.MulByNonResidue(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitMulByNonResidue(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2MulByNonResidueCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2MulByNonResidueCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)
	assignment := &Fp2MulByNonResidueCircuit{
		A: FromE2(&a),
		C: FromE2(&c),
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

type Fp2MulByElementCircuit struct {
	A Fp2
	B frontend.Variable
	C Fp2 `gnark:",public"`
}

func (circuit *Fp2MulByElementCircuit) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := e.MulByElement(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitMulByElement(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2MulByElementCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2MulByElementCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E2
	_, _ = a.SetRandom()
	var b bn254_fp.Element
	_, _ = b.SetRandom()
	c.MulByElement(&a, &b)
	assignment := &Fp2MulByElementCircuit{
		A: FromE2(&a),
		B: grumpkin_fr.Element(b),
		C: FromE2(&c),
	}
	start_witness := time.Now()
	// Generate witness
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

type Fp2Exp struct {
	A Fp2
	B frontend.Variable
	C Fp2 `gnark:",public"`
}

func (circuit *Fp2Exp) Define(api frontend.API) error {
	e := Ext2{api: api}
	expected := e.Exp(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitExp(t *testing.T) {
	// Define the circuit
	// Replace with an existing circuit type, e.g., SubCircuit
	var circuit Fp2Exp
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of Fp2Exp", r1cs.GetNbConstraints())
	var a, c bn254.E2
	_, _ = a.SetRandom()
	var b bn254_fp.Element
	_, _ = b.SetRandom()
	var bBigInt big.Int
	b.BigInt(&bBigInt)

	c.Exp(a, &bBigInt)
	assignment := &Fp2Exp{
		A: FromE2(&a),
		B: grumpkin_fr.Element(b),
		C: FromE2(&c),
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

// type Fp2DivUncheckedCircuit struct {
// 	A Fp2
// 	B Fp2
// 	C Fp2 `gnark:",public"`
// }

// func (circuit *Fp2DivUncheckedCircuit) Define(api frontend.API) error {
// 	e := Ext2{api: api}
// 	expected := e.Fp2DivUnchecked(&circuit.A, &circuit.B)
// 	e.AssertIsEqual(expected, &circuit.C)
// 	return nil
// }

// func TestCircuitFp2DivUnchecked(t *testing.T) {
// 	// Define the circuit
// 	// Replace with an existing circuit type, e.g., SubCircuit
// 	var circuit Fp2DivUncheckedCircuit
// 	// Compile the circuit into an R1CS
// 	start := time.Now()
// 	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
// 	if err != nil {
// 		t.Fatalf("Error compiling circuit: %s", err)
// 	}
// 	duration := time.Since(start)
// 	fmt.Printf("Circuit compiled in: %s\n", duration)

// 	fmt.Println("number of constraints of Fp2Exp", r1cs.GetNbConstraints())
// 	var a, b, c bn254.E2

// 	_, _ = a.SetRandom()
// 	_ = b.SetZero()
// 	_ = c.SetZero()

// 	// _, _ = b.SetRandom()
// 	// c.Div(&a, &b)

// 	// fmt.Println("c is ", c)

// 	assignment := &Fp2DivUncheckedCircuit{
// 		A: FromE2(&a),
// 		B: FromE2(&b),
// 		C: FromE2(&c),
// 	}

// 	// Generate witness
// 	start_witness := time.Now()
// 	witness, err := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	_, err = r1cs.Solve(witness)
// 	if err != nil {
// 		fmt.Println("Error solving the r1cs", err)
// 		return
// 	}
// 	duration_witness := time.Since(start_witness)
// 	fmt.Printf("Witness generated in: %s\n", duration_witness)

// }
