package pairing

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	field_tower "github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/field_tower"
	groups "github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/groups"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type FrobeniusCircuit struct {
	A field_tower.Fp12
	C field_tower.Fp12 `gnark:",public"`
}

func (circuit *FrobeniusCircuit) Define(api frontend.API) error {
	e2 := field_tower.New(api)
	e12 := field_tower.NewExt12(api)
	expected := Frobenius(e2, &circuit.A)
	e12.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitFrobenius(t *testing.T) {

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
	e2 := field_tower.New(api)
	e12 := field_tower.NewExt12(api)
	expected := FrobeniusSquare(e2, &circuit.A)
	e12.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitFrobeniusSquare(t *testing.T) {

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
	e2 := field_tower.New(api)
	expected := FrobeniusCube(e2, &circuit.A)
	e12 := field_tower.NewExt12(api)
	e12.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitFrobeniusCube(t *testing.T) {

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
	e2 := field_tower.New(api)
	e6 := field_tower.NewExt6(api)
	expected := MulBy01(e2, &circuit.A, &circuit.B, &circuit.C)
	e6.AssertIsEqual(expected, &circuit.D)
	return nil
}

func TestCircuitMulBy01(t *testing.T) {

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
	e2 := field_tower.New(api)
	e6 := field_tower.NewExt6(api)
	e12 := field_tower.NewExt12(api)
	expected := MulBy034(e2, e6, &circuit.A, &circuit.B, &circuit.C, &circuit.D)
	e12.AssertIsEqual(expected, &circuit.E)
	return nil
}

func TestCircuitMulBy034(t *testing.T) {

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
	e2 := field_tower.New(api)
	e12 := field_tower.NewExt12(api)
	expected := FinalExp(e2, e12, &circuit.A)
	e12.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitFinalExp(t *testing.T) {

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
	A groups.G2Affine
	B groups.G1Projective
	C field_tower.Fp12 `gnark:",public"`
}

func (circuit *PairingCircuit) Define(api frontend.API) error {
	pairing_api := New(api)
	expected := pairing_api.Pairing(&circuit.A, &circuit.B)
	e12 := field_tower.NewExt12(api)
	e12.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestCircuitPairing(t *testing.T) {

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
		A: groups.G2AffineFromBNG2Affine(&Q[0]),
		B: groups.FromG1Affine(&P[0]),
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

type MillerUniformCircuit struct {
	FIn       field_tower.Fp12 `gnark:",public"`
	P         groups.G1Affine  `gnark:",public"`
	Ell_Coeff [2]field_tower.Fp6
	FOut      [3]field_tower.Fp12
	Bit       frontend.Variable
}

func (circuit *MillerUniformCircuit) Define(api frontend.API) error {
	pairing_api := New(api)

	f1, f2, f3 := pairing_api.MillerLoopStep(&circuit.FIn, circuit.Ell_Coeff[:], &circuit.P, circuit.Bit)
	e12 := field_tower.NewExt12(api)
	e12.AssertIsEqual(&f1, &circuit.FOut[0])
	e12.AssertIsEqual(&f2, &circuit.FOut[1])
	e12.AssertIsEqual(&f3, &circuit.FOut[2])

	return nil
}

func TestCircuitMillerStep(t *testing.T) {
	// Define the circuit

	var circuit MillerUniformCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of MillerUniformCircuit", r1cs.GetNbConstraints())

	_, _, g1GenAff, g2GenAff := bn254.Generators()

	var P bn254.G1Affine
	var Q bn254.G2Affine

	scalar, _ := rand.Int(rand.Reader, bn254_fr.Modulus())
	P.ScalarMultiplication(&g1GenAff, scalar)
	Q.ScalarMultiplication(&g2GenAff, scalar)

	bits := []int{
		0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
		0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
		-1, 0, 0, 0, 1, 0, 1,
	}
	var c bn254.E12
	// make FOut an array of lenght 3 for FOut
	var FOut [3]field_tower.Fp12

	Ell_coeff, _ := EllCoeffs_fn(&Q)
	var FIn bn254.E12
	FIn.SetOne()

	var Ell_coeff_new [2]field_tower.Fp6

	for i := 0; i < 2; i++ {
		Ell_coeff_new[i] = field_tower.FromE6(&Ell_coeff[i])
	}
	f1, f2, f3 := MillerLoopStep_fn(&FIn, Ell_coeff[0:2], &P, bits[0])
	FOut[0] = field_tower.FromE12(&f1)
	FOut[1] = field_tower.FromE12(&f2)
	FOut[2] = field_tower.FromE12(&f3)
	
	assignment := &MillerUniformCircuit{
		FIn:       field_tower.FromE12(c.SetOne()),
		P:         groups.AffineFromG1Affine(&P),
		Ell_Coeff: Ell_coeff_new,
		FOut:      FOut,
		Bit:       bits[0],
	}

	start_witness := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	wit, err_1 := r1cs.Solve(witness)
	if err_1 != nil {
		fmt.Println("Error solving the r1cs", err_1)
		return
	}

	z := wit.(*cs.R1CSSolution).W

	duration_witness := time.Since(start_witness)
	fmt.Printf("Witness generated in: %s\n", duration_witness)

	var extendZ grumpkin_fr.Vector
	zLen := len(z)

	n := 64
	for idx := 0; idx < zLen; idx++ {
		extendZ = append(extendZ, z[idx])
	}

	var FIn_val field_tower.Fp12
	for idx := 1; idx < 64; idx++ {
		println("idx ========================================================", idx)

		FIn_val.A0.A0.A0 = z[51]
		FIn_val.A0.A0.A1 = z[52]
		FIn_val.A0.A1.A0 = z[53]
		FIn_val.A0.A1.A1 = z[54]
		FIn_val.A0.A2.A0 = z[55]
		FIn_val.A0.A2.A1 = z[56]
		FIn_val.A1.A0.A0 = z[57]
		FIn_val.A1.A0.A1 = z[58]
		FIn_val.A1.A1.A0 = z[59]
		FIn_val.A1.A1.A1 = z[60]
		FIn_val.A1.A2.A0 = z[61]
		FIn_val.A1.A2.A1 = z[62]

		for i := 0; i < 2; i++ {
			Ell_coeff_new[i] = field_tower.FromE6(&Ell_coeff[idx*2+i])
		}

		f1, f2, f3 = MillerLoopStep_fn(&f3, Ell_coeff[idx*2:idx*2+2], &P, bits[n-1-idx])
		FOut[0] = field_tower.FromE12(&f1)
		FOut[1] = field_tower.FromE12(&f2)
		FOut[2] = field_tower.FromE12(&f3)

		assignment := &MillerUniformCircuit{
			FIn:       FIn_val,
			P:         groups.AffineFromG1Affine(&P),
			Ell_Coeff: Ell_coeff_new,
			FOut:      FOut,
			Bit:       bits[n-1-idx],
		}

		witness, _ := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		wit, err_1 := r1cs.Solve(witness)
		if err_1 != nil {
			fmt.Println("Error solving the r1cs", err_1)
			return
		}

		z = wit.(*cs.R1CSSolution).W
		for idx := 0; idx < len(z); idx++ {
			extendZ = append(extendZ, z[idx])
		}

	}
	duration = time.Since(start)
	fmt.Printf("Witness generation time 2 : %s\n", duration)
}

type EllCoeffsCircuit struct {
	Q         groups.G2Affine
	Ell_coeff [130]field_tower.Fp6
}

func (circuit *EllCoeffsCircuit) Define(api frontend.API) error {
	pairing_api := New(api)
	Ell_coeffsss, _ := pairing_api.EllCoeffs(&circuit.Q)
	e6 := field_tower.NewExt6(api)
	for i := 0; i < 130; i++ {
		e6.AssertIsEqual(&Ell_coeffsss[i], &circuit.Ell_coeff[i])
	}
	return nil
}

func TestCircuitEllCoeffs(t *testing.T) {
	var circuit EllCoeffsCircuit
	// Compile the circuit into an R1CS
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n", duration)

	fmt.Println("number of constraints of EllCoeffsCircuit", r1cs.GetNbConstraints())

	_, a := randomG1G2Affines()

	Ell_coeff, _ := EllCoeffs_fn(&a)

	var Ell_coeff_new [130]field_tower.Fp6

	for i := 0; i < 130; i++ {
		Ell_coeff_new[i] = field_tower.FromE6(&Ell_coeff[i])
	}

	assignment := &EllCoeffsCircuit{
		Q:         groups.G2AffineFromBNG2Affine(&a),
		Ell_coeff: Ell_coeff_new,
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
