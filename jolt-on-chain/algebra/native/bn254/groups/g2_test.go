package g1ops

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type G2AddCircuit struct {
	A, B, C G2Affine
}

func (circuit *G2AddCircuit) Define(api frontend.API) error {
	e := NewG2(api)
	expected := e.G2Add(&circuit.A, &circuit.B)
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

	output_constraints := ExtractConstraints(r1cs)

	_, _, _, in1 := bn254.Generators()
	_, _, _, in2 := bn254.Generators()
	// in2 = *in2.Double(&in2)
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

	solution, err_1 := r1cs.Solve(witness)
	if err_1 != nil {
		fmt.Println("Error solving the r1cs", err_1)
		return
	}
	duration_witness := time.Since(start_witness)
	fmt.Printf("Witness generated in: %s\n", duration_witness)

	// Serialize and export solution (witness)
	solutionJSON, err := json.MarshalIndent(solution, "", "  ")
	if err != nil {
		t.Fatalf("Error serializing R1CS: %s", err)
	}
	err = os.WriteFile("solution.json", solutionJSON, 0644)
	if err != nil {
		t.Fatalf("Error writing JSON file: %s", err)
	}

	// Serialize and export r1cs
	r1csJSON, err := json.MarshalIndent(r1cs, "", "  ")
	if err != nil {
		t.Fatalf("Error serializing R1CS: %s", err)
	}
	err = os.WriteFile("r1cs.json", r1csJSON, 0644)
	if err != nil {
		t.Fatalf("Error writing JSON file: %s", err)
	}

	// Type assertion
	sol := solution.(*cs.R1CSSolution)
	// z is the full witness
	z := sol.W

	// println(ecc.BN254.ScalarField())
	CheckInnerProduct(t, output_constraints, z)
}

type G2NegCircuit struct {
	A, B G2Affine
}

func (circuit *G2NegCircuit) Define(api frontend.API) error {
	e := NewG2(api)
	expected := e.G2Neg(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)

	return nil
}

func TestCircuitG2Neg(t *testing.T) {
	var circuit G2NegCircuit
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of G2Add", r1cs.GetNbConstraints())

	output_constraints := ExtractConstraints(r1cs)

	_, in1 := randomG1G2Affines()
	var res bn254.G2Affine
	res.Neg(&in1)

	assignment := G2NegCircuit{
		A: FromBNG2Affine(&in1),
		B: FromBNG2Affine(&res),
	}

	// Generate witness
	start_witness := time.Now()
	witness, err := frontend.NewWitness(&assignment, ecc.GRUMPKIN.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	solution, err_1 := r1cs.Solve(witness)
	if err_1 != nil {
		fmt.Println("Error solving the r1cs", err_1)
		return
	}
	duration_witness := time.Since(start_witness)
	fmt.Printf("Witness generated in: %s\n", duration_witness)

	// Serialize and export solution (witness)
	solutionJSON, err := json.MarshalIndent(solution, "", "  ")
	if err != nil {
		t.Fatalf("Error serializing R1CS: %s", err)
	}
	err = os.WriteFile("solution.json", solutionJSON, 0644)
	if err != nil {
		t.Fatalf("Error writing JSON file: %s", err)
	}

	// Serialize and export r1cs
	r1csJSON, err := json.MarshalIndent(r1cs, "", "  ")
	if err != nil {
		t.Fatalf("Error serializing R1CS: %s", err)
	}
	err = os.WriteFile("r1cs.json", r1csJSON, 0644)
	if err != nil {
		t.Fatalf("Error writing JSON file: %s", err)
	}

	// Type assertion
	sol := solution.(*cs.R1CSSolution)
	// z is the full witness
	z := sol.W

	// println(ecc.BN254.ScalarField())
	CheckInnerProduct(t, output_constraints, z)
}

type G2SubCircuit struct {
	A, B, C G2Affine
}

func (circuit *G2SubCircuit) Define(api frontend.API) error {
	e := NewG2(api)
	expected := e.G2Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestCircuitG2Sub(t *testing.T) {
	var circuit G2SubCircuit
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of G2Add", r1cs.GetNbConstraints())

	output_constraints := ExtractConstraints(r1cs)

	_, in1 := randomG1G2Affines()
	_, in2 := randomG1G2Affines()
	var res bn254.G2Affine
	res.Sub(&in1, &in2)

	assignment := G2SubCircuit{
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

	solution, err_1 := r1cs.Solve(witness)
	if err_1 != nil {
		fmt.Println("Error solving the r1cs", err_1)
		return
	}
	duration_witness := time.Since(start_witness)
	fmt.Printf("Witness generated in: %s\n", duration_witness)

	// Serialize and export solution (witness)
	solutionJSON, err := json.MarshalIndent(solution, "", "  ")
	if err != nil {
		t.Fatalf("Error serializing R1CS: %s", err)
	}
	err = os.WriteFile("solution.json", solutionJSON, 0644)
	if err != nil {
		t.Fatalf("Error writing JSON file: %s", err)
	}

	// Serialize and export r1cs
	r1csJSON, err := json.MarshalIndent(r1cs, "", "  ")
	if err != nil {
		t.Fatalf("Error serializing R1CS: %s", err)
	}
	err = os.WriteFile("r1cs.json", r1csJSON, 0644)
	if err != nil {
		t.Fatalf("Error writing JSON file: %s", err)
	}

	// Type assertion
	sol := solution.(*cs.R1CSSolution)
	// z is the full witness
	z := sol.W

	// println(ecc.BN254.ScalarField())
	CheckInnerProduct(t, output_constraints, z)
}

type G2DoubleCircuit struct {
	A, B G2Affine
}

func (circuit *G2DoubleCircuit) Define(api frontend.API) error {
	e := NewG2(api)
	expected := e.G2Double(&circuit.A)
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

	fmt.Println("number of constraints of G2Add", r1cs.GetNbConstraints())

	// output_constraints := ExtractConstraints(r1cs)

	// _, in1 := randomG1G2Affines()
	_, _, _, in1 := bn254.Generators()
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

	// // Serialize and export solution (witness)
	// solutionJSON, err := json.MarshalIndent(solution, "", "  ")
	// if err != nil {
	// 	t.Fatalf("Error serializing R1CS: %s", err)
	// }
	// err = os.WriteFile("solution.json", solutionJSON, 0644)
	// if err != nil {
	// 	t.Fatalf("Error writing JSON file: %s", err)
	// }

	// // Serialize and export r1cs
	// r1csJSON, err := json.MarshalIndent(r1cs, "", "  ")
	// if err != nil {
	// 	t.Fatalf("Error serializing R1CS: %s", err)
	// }
	// err = os.WriteFile("r1cs.json", r1csJSON, 0644)
	// if err != nil {
	// 	t.Fatalf("Error writing JSON file: %s", err)
	// }

	// // Type assertion
	// sol := solution.(*cs.R1CSSolution)
	// // z is the full witness
	// z := sol.W

	// // println(ecc.BN254.ScalarField())
	// CheckInnerProduct(t, output_constraints, z)
}

// number of constraints seems incorrect

// type G2DoubleNCircuit struct {
// 	A, B G2Affine
// 	n    int
// }

// func (circuit *G2DoubleNCircuit) Define(api frontend.API) error {
// 	e := NewG2(api)
// 	expected := e.G2DoubleN(&circuit.A, circuit.n)
// 	e.AssertIsEqual(expected, &circuit.B)

// 	return nil
// }

// func TestCircuitG2DoubleN(t *testing.T) {
// 	var circuit G2DoubleNCircuit
// 	start := time.Now()
// 	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
// 	if err != nil {
// 		t.Fatalf("Error compiling circuit: %s", err)
// 	}
// 	duration := time.Since(start)
// 	fmt.Printf("Circuit compiled in: %s\n", duration)

// 	fmt.Println("number of constraints of G2Add", r1cs.GetNbConstraints())

// 	// output_constraints := ExtractConstraints(r1cs)

// 	_, in1 := randomG1G2Affines()
// 	var res bn254.G2Affine
// 	res = in1
// 	assignment := G2DoubleNCircuit{
// 		A: FromBNG2Affine(&in1),
// 		B: FromBNG2Affine(&res),
// 		n: 10,
// 	}
// 	// for i := 0; i < assignment.n-2; i++ {
// 	// 	res.Double(&res)
// 	// }
// 	// Generate witness
// 	start_witness := time.Now()
// 	witness, err := frontend.NewWitness(&assignment, ecc.GRUMPKIN.ScalarField())
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	_, err_1 := r1cs.Solve(witness)
// 	if err_1 != nil {
// 		fmt.Println("Error solving the r1cs", err_1)
// 		return
// 	}
// 	duration_witness := time.Since(start_witness)
// 	fmt.Printf("Witness generated in: %s\n", duration_witness)
// }

type G2DoubleAndAddCircuit struct {
	A, B, C G2Affine
}

func (circuit *G2DoubleAndAddCircuit) Define(api frontend.API) error {
	e := NewG2(api)
	expected := e.G2DoubleAndAdd(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestCircuitG2DoubleAndAdd(t *testing.T) {
	var circuit G2DoubleAndAddCircuit
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of G2Add", r1cs.GetNbConstraints())

	// output_constraints := ExtractConstraints(r1cs)

	_, _, _, in1 := bn254.Generators()
	_, _, _, in2 := bn254.Generators()

	var res bn254.G2Affine
	res.Double(&in1).
		Add(&res, &in2)
	// fmt.Println("in1 is ", in1)
	fmt.Println("res is ", res)
	var sum_res bn254.G2Affine
	sum_res.Add(&in1, &in1)
	sum_res.Add(&sum_res, &in1)
	fmt.Println("sum_res is ", sum_res)

	assignment := G2DoubleAndAddCircuit{
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

	// // Serialize and export solution (witness)
	// solutionJSON, err := json.MarshalIndent(solution, "", "  ")
	// if err != nil {
	// 	t.Fatalf("Error serializing R1CS: %s", err)
	// }
	// err = os.WriteFile("solution.json", solutionJSON, 0644)
	// if err != nil {
	// 	t.Fatalf("Error writing JSON file: %s", err)
	// }

	// // Serialize and export r1cs
	// r1csJSON, err := json.MarshalIndent(r1cs, "", "  ")
	// if err != nil {
	// 	t.Fatalf("Error serializing R1CS: %s", err)
	// }
	// err = os.WriteFile("r1cs.json", r1csJSON, 0644)
	// if err != nil {
	// 	t.Fatalf("Error writing JSON file: %s", err)
	// }

	// // Type assertion
	// sol := solution.(*cs.R1CSSolution)
	// // z is the full witness
	// z := sol.W

	// // println(ecc.BN254.ScalarField())
	// CheckInnerProduct(t, output_constraints, z)
}
