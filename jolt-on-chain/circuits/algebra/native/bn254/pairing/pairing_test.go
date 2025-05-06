package pairing

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	field_tower "github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/field_tower"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type FrobeniusCircuit struct {
	A field_tower.Fp12
	C field_tower.Fp12 `gnark:",public"`
}

func (circuit *FrobeniusCircuit) Define(api frontend.API) error {

	expected := Frobenius(&api, &circuit.A)

	e12 := field_tower.NewExt12(api)
	e12.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobenius(t *testing.T) {

	var circuit FrobeniusCircuit

	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of FrobeniusCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E12
	_, _ = a.SetRandom()

	c.Frobenius(&a)

	assignment := &FrobeniusCircuit{
		A: field_tower.FromE12(&a),
		C: field_tower.FromE12(&c),
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

type FrobeniusSquareCircuit struct {
	A field_tower.Fp12
	C field_tower.Fp12 `gnark:",public"`
}

func (circuit *FrobeniusSquareCircuit) Define(api frontend.API) error {
	expected := FrobeniusSquare(&api, &circuit.A)

	e12 := field_tower.NewExt12(api)
	e12.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobenius2(t *testing.T) {

	var circuit FrobeniusSquareCircuit

	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of FrobeniusSquareCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E12
	_, _ = a.SetRandom()

	c.FrobeniusSquare(&a)

	assignment := &FrobeniusSquareCircuit{
		A: field_tower.FromE12(&a),
		C: field_tower.FromE12(&c),
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

type FrobeniusCubeCircuit struct {
	A field_tower.Fp12
	C field_tower.Fp12 `gnark:",public"`
}

func (circuit *FrobeniusCubeCircuit) Define(api frontend.API) error {
	expected := FrobeniusCube(&api, &circuit.A)
	e12 := field_tower.NewExt12(api)
	e12.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusCube(t *testing.T) {

	var circuit FrobeniusCubeCircuit

	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of FrobeniusCubeCircuit", r1cs.GetNbConstraints())
	var a, c bn254.E12
	_, _ = a.SetRandom()

	c.FrobeniusCube(&a)

	assignment := &FrobeniusCubeCircuit{
		A: field_tower.FromE12(&a),
		C: field_tower.FromE12(&c),
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

type MulBy01Circuit struct {
	A field_tower.Fp6
	B field_tower.Fp2
	C field_tower.Fp2
	D field_tower.Fp6 `gnark:",public"`
}

func (circuit *MulBy01Circuit) Define(api frontend.API) error {
	expected := MulBy01(&api, &circuit.A, &circuit.B, &circuit.C)
	e6 := field_tower.NewExt6(api)
	e6.AssertIsEqual(expected, &circuit.D)
	return nil
}

func TestMulBy01(t *testing.T) {

	var circuit MulBy01Circuit

	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of MulBy01Circuit", r1cs.GetNbConstraints())
	var a, d bn254.E6
	_, _ = a.SetRandom()

	var b, c bn254.E2
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()

	d = a
	d.MulBy01(&b, &c)

	assignment := &MulBy01Circuit{
		A: field_tower.FromE6(&a),
		B: field_tower.FromE2(&b),
		C: field_tower.FromE2(&c),
		D: field_tower.FromE6(&d),
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

type MulBy034Circuit struct {
	A field_tower.Fp12
	B field_tower.Fp2
	C field_tower.Fp2
	D field_tower.Fp2
	E field_tower.Fp12 `gnark:",public"`
}

func (circuit *MulBy034Circuit) Define(api frontend.API) error {
	expected := MulBy034(&api, &circuit.A, &circuit.B, &circuit.C, &circuit.D)
	e12 := field_tower.NewExt12(api)
	e12.AssertIsEqual(expected, &circuit.E)
	return nil
}

func TestMulBy034(t *testing.T) {

	var circuit MulBy034Circuit

	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of MulBy034Circuit", r1cs.GetNbConstraints())
	var a, e bn254.E12
	_, _ = a.SetRandom()

	var b, c, d bn254.E2
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()
	_, _ = d.SetRandom()

	e = a
	e.MulBy034(&b, &c, &d)

	assignment := &MulBy034Circuit{
		A: field_tower.FromE12(&a),
		B: field_tower.FromE2(&b),
		C: field_tower.FromE2(&c),
		D: field_tower.FromE2(&d),
		E: field_tower.FromE12(&e),
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

type FinalExponentiationCircuit struct {
	A field_tower.Fp12
	C field_tower.Fp12 `gnark:",public"`
}

func (circuit *FinalExponentiationCircuit) Define(api frontend.API) error {

	expected := FinalExp(&api, &circuit.A)
	e12 := field_tower.NewExt12(api)
	e12.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFinalExponentiation(t *testing.T) {

	var circuit FinalExponentiationCircuit

	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of FinalExponentiationCircuit", r1cs.GetNbConstraints())
	var a, c bn254.GT
	_, _ = a.SetRandom()

	c = bn254.FinalExponentiation(&a)

	assignment := &FinalExponentiationCircuit{
		A: field_tower.FromE12(&a),
		C: field_tower.FromE12(&c),
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

type PairingCircuit struct {
	A G2Affine
	B G1Projective
	C field_tower.Fp12 `gnark:",public"`
}

func (circuit *PairingCircuit) Define(api frontend.API) error {

	expected := Pairing(&api, &circuit.A, &circuit.B)
	e12 := field_tower.NewExt12(api)
	e12.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestPairing(t *testing.T) {

	var circuit PairingCircuit

	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of PairingCircuit", r1cs.GetNbConstraints())

	_, _, g1GenAff, g2GenAff := bn254.Generators()

	var ag1 bn254.G1Affine
	var bg2 bn254.G2Affine

	scalar, _ := rand.Int(rand.Reader, bn254_fr.Modulus())
	ag1.ScalarMultiplication(&g1GenAff, scalar)
	bg2.ScalarMultiplication(&g2GenAff, scalar)

	P := []bn254.G1Affine{ag1}
	Q := []bn254.G2Affine{bg2}

	res, _ := bn254.Pair(P, Q)

	assignment := &PairingCircuit{
		A: G2AffineFromBNG2Affine(&Q[0]),
		B: FromG1Affine(&P[0]),
		C: field_tower.FromE12(&res),
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
