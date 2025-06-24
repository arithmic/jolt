package pairing

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/arithmic/gnark/constraint"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	field_tower "github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"
	groups "github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"

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

// // Test the miller output from witness with the MillerLoop function of gnark
// func TestCircuitMillerLoopUniformWithInterface(t *testing.T) {
// 	// Define the circuit
// 	n := 64

// 	var dummyCircuit *MillerStepCircuit

// 	circuits := make([]*MillerStepCircuit, n)

// 	_, _, g1GenAff, g2GenAff := bn254.Generators()

// 	var P bn254.G1Affine
// 	var Q bn254.G2Affine

// 	scalar, _ := rand.Int(rand.Reader, bn254_fr.Modulus())
// 	P.ScalarMultiplication(&g1GenAff, scalar)
// 	Q.ScalarMultiplication(&g2GenAff, scalar)

// 	bits := []int{
// 		0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
// 		0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
// 		-1, 0, 0, 0, 1, 0, 1,
// 	}

// 	Rin := ToProjective_fn(&Q)
// 	var neg_Q bn254.G2Affine
// 	neg_Q.X = Q.X
// 	neg_Q.Y.A1.Neg(&Q.Y.A1)
// 	neg_Q.Y.A0.Neg(&Q.Y.A0)

// 	var FIn bn254.E12
// 	FIn.SetOne()

// 	Rout, f1, f2, f3 := MillerLoopStepIntegrated_fn(&Rin, &Q, &neg_Q, &P, &FIn, bits[n-1])

// 	var FOut [3]field_tower.Fp12

// 	FOut[0] = field_tower.FromE12(&f1)
// 	FOut[1] = field_tower.FromE12(&f2)
// 	FOut[2] = field_tower.FromE12(&f3)

// 	for i := 0; i < n; i++ {
// 		circuits[i] = &MillerStepCircuit{
// 			FIn:  field_tower.FromE12(&FIn),
// 			P:    groups.AffineFromG1Affine(&P),
// 			Rin:  groups.FromBNG2Affine(&Q),
// 			Q:    groups.G2AffineFromBNG2Affine(&Q),
// 			NegQ: groups.G2AffineFromBNG2Affine(&neg_Q),
// 			Rout: G2ProjectiveFromBNG2Projective(&Rout),
// 			FOut: FOut,
// 			Bit:  bits[n-1-i],

// 			fIn:  FIn,
// 			p:    P,
// 			rin:  Rin,
// 			q:    Q,
// 			negQ: neg_Q,
// 			rout: G2Projective{X: Rout.X, Y: Rout.Y, Z: Rout.Z},
// 			bit:  bits[n-1-i],
// 			fOut: [3]bn254.E12{f1, f2, f3},
// 		}
// 	}

// 	dummyCircuit = &MillerStepCircuit{}
// 	r1cs := dummyCircuit.Compile()
// 	extendZ := dummyCircuit.GenerateWitness(circuits, r1cs, 64)

// 	// extract values from circuit n - 1 and put them as inputs for MillerEllFinalStepCircuit circuit
// 	var miller_final_circuit *MillerEllFinalStepCircuit

// 	final_circuits := make([]*MillerEllFinalStepCircuit, 1)

// 	final_circuits[0] = &MillerEllFinalStepCircuit{
// 		FIn:  circuits[n-1].FOut[2],
// 		P:    groups.AffineFromG1Affine(&P),
// 		Rin:  circuits[n-1].Rout,
// 		Q:    groups.G2AffineFromBNG2Affine(&Q),
// 		Rout: circuits[n-1].Rout,    // dummy value
// 		FOut: circuits[n-1].FOut[0], // dummy value
// 		fIn:  circuits[n-1].fOut[2],
// 		fOut: circuits[n-1].fOut[0], // dummy value
// 		p:    P,
// 		rin:  circuits[n-1].rout,
// 		q:    Q,
// 		rout: circuits[n-1].rout, // dummy value
// 	}
// 	miller_final_circuit = &MillerEllFinalStepCircuit{}

// 	r1cs_1 := miller_final_circuit.Compile()
// 	final_witness := miller_final_circuit.GenerateWitness(final_circuits, r1cs_1, 1)

// 	for i := 0; i < len(final_witness); i++ {
// 		extendZ = append(extendZ, final_witness[i])
// 	}

// 	P_arr := []bn254.G1Affine{P}
// 	Q_arr := []bn254.G2Affine{Q}
// 	actual_miller_res, _ := bn254.MillerLoop(P_arr, Q_arr)
// 	actual_res_after_final_exp := bn254.FinalExponentiation(&actual_miller_res)

// 	miller_final_res_from_witness := bn254.E12{}

// 	// 22976 is the length of witness from MillerUniformCircuit
// 	miller_final_res_from_witness.C0.B0.A0.SetString(extendZ[22976+19].String())
// 	miller_final_res_from_witness.C0.B0.A1.SetString(extendZ[22976+20].String())
// 	miller_final_res_from_witness.C0.B1.A0.SetString(extendZ[22976+21].String())
// 	miller_final_res_from_witness.C0.B1.A1.SetString(extendZ[22976+22].String())
// 	miller_final_res_from_witness.C0.B2.A0.SetString(extendZ[22976+23].String())
// 	miller_final_res_from_witness.C0.B2.A1.SetString(extendZ[22976+24].String())
// 	miller_final_res_from_witness.C1.B0.A0.SetString(extendZ[22976+25].String())
// 	miller_final_res_from_witness.C1.B0.A1.SetString(extendZ[22976+26].String())
// 	miller_final_res_from_witness.C1.B1.A0.SetString(extendZ[22976+27].String())
// 	miller_final_res_from_witness.C1.B1.A1.SetString(extendZ[22976+28].String())
// 	miller_final_res_from_witness.C1.B2.A0.SetString(extendZ[22976+29].String())
// 	miller_final_res_from_witness.C1.B2.A1.SetString(extendZ[22976+30].String())

// 	res_after_final_exp_for_witness := bn254.FinalExponentiation(&miller_final_res_from_witness)

// 	val := actual_res_after_final_exp.Equal(&res_after_final_exp_for_witness)
// 	if val == false {
// 		fmt.Println("The result is NOT equal after exponentiation with gnark functions")
// 	} else {
// 		fmt.Println("The result is equal after exponentiation with gnark functions")
// 	}
// }

func TestPairingUniformCircuit(t *testing.T) {
	var one grumpkin_fr.Element
	one.SetOne()

	// Set up inputs
	var P bn254.G1Affine
	var Q bn254.G2Affine

	_, _, g1Gen, g2Gen := bn254.Generators()
	scalar, _ := rand.Int(rand.Reader, bn254_fr.Modulus())
	P.ScalarMultiplication(&g1Gen, scalar)
	Q.ScalarMultiplication(&g2Gen, scalar)

	// Compute expected result from native bn254
	Ps := []bn254.G1Affine{P}
	Qs := []bn254.G2Affine{Q}
	nativeML, _ := bn254.MillerLoop(Ps, Qs)
	nativeFE := bn254.FinalExponentiation(&nativeML)

	// Miller loop step circuits
	var FIn bn254.E12
	FIn.SetOne()

	var negQ bn254.G2Affine
	negQ.X = Q.X
	negQ.Y.A0.Neg(&Q.Y.A0)
	negQ.Y.A1.Neg(&Q.Y.A1)

	// Combine into final pairing circuit
	pairingCircuit := &PairingUniformCircuit{
		P: groups.AffineFromG1Affine(&P),
		Q: groups.G2AffineFromBNG2Affine(&Q),
		// NegQ:           groups.G2AffineFromBNG2Affine(&negQ),
		Res: field_tower.FromE12(&nativeML),
		p:   P,
		q:   Q,
		// negQ:           negQ,
		res:            nativeML,
		Miller_uniform: &MillerUniformCircuit{},
		Miller_final:   &MillerEllFinalStepCircuit{},
	}

	pair_r1cs := pairingCircuit.CreateStepCircuits()
	witness := pairingCircuit.GenerateWitness(pair_r1cs)

	// Extract final E12 from witness
	var resFromCircuit bn254.E12
	// offset := len(witness) - 12
	resFromCircuit.C0.B0.A0.SetString(witness[22739+0].String())
	resFromCircuit.C0.B0.A1.SetString(witness[22739+1].String())
	resFromCircuit.C0.B1.A0.SetString(witness[22739+2].String())
	resFromCircuit.C0.B1.A1.SetString(witness[22739+3].String())
	resFromCircuit.C0.B2.A0.SetString(witness[22739+4].String())
	resFromCircuit.C0.B2.A1.SetString(witness[22739+5].String())
	resFromCircuit.C1.B0.A0.SetString(witness[22739+6].String())
	resFromCircuit.C1.B0.A1.SetString(witness[22739+7].String())
	resFromCircuit.C1.B1.A0.SetString(witness[22739+8].String())
	resFromCircuit.C1.B1.A1.SetString(witness[22739+9].String())
	resFromCircuit.C1.B2.A0.SetString(witness[22739+10].String())
	resFromCircuit.C1.B2.A1.SetString(witness[22739+11].String())

	circuitFinalExp := bn254.FinalExponentiation(&resFromCircuit)

	if !circuitFinalExp.Equal(&nativeFE) {
		t.Fatal("Mismatch between circuit final exponentiation and expected result")
	} else {
		fmt.Println("Pairing result matches native final exponentiation")
	}
}

type Constraint struct {
	A map[string]string
	B map[string]string
	C map[string]string
}

func ExtractConstraints(r1cs constraint.ConstraintSystem) ([]Constraint, int, int, int) {
	var outputConstraints []Constraint
	var aCount, bCount, cCount int

	// Assert to R1CS to get access to R1CS-specific methods
	nR1CS, ok := r1cs.(constraint.R1CS)
	if !ok {
		return outputConstraints, 0, 0, 0 // or handle error
	}
	constraints := nR1CS.GetR1Cs()
	for _, r1c := range constraints {
		singular := Constraint{
			A: make(map[string]string),
			B: make(map[string]string),
			C: make(map[string]string),
		}

		for _, term := range r1c.L {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.A[col] = val
			aCount++
		}
		for _, term := range r1c.R {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.B[col] = val
			bCount++
		}
		for _, term := range r1c.O {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.C[col] = val
			cCount++
		}

		outputConstraints = append(outputConstraints, singular)
	}

	return outputConstraints, aCount, bCount, cCount
}

func TestMillerUniformCircuitStepOnly(t *testing.T) {
	// n := 64

	_, _, g1GenAff, g2GenAff := bn254.Generators()

	var P bn254.G1Affine
	var Q bn254.G2Affine

	scalar, _ := rand.Int(rand.Reader, bn254_fr.Modulus())
	P.ScalarMultiplication(&g1GenAff, scalar)
	Q.ScalarMultiplication(&g2GenAff, scalar)

	var negQ bn254.G2Affine
	negQ.X = Q.X
	negQ.Y.A1.Neg(&Q.Y.A1)
	negQ.Y.A0.Neg(&Q.Y.A0)

	// Construct public inputs
	P_circuit := groups.AffineFromG1Affine(&P)
	Q_circuit := groups.G2AffineFromBNG2Affine(&Q)
	// NegQ_circuit := groups.G2AffineFromBNG2Affine(&negQ)

	millerUniform := MillerUniformCircuit{
		P: P_circuit,
		Q: Q_circuit,
		// NegQ:                NegQ_circuit,
		p: P,
		q: Q,
		// negQ:                negQ,
		Miller_step_circuit: &MillerStepCircuit{},
	}

	// Compile step circuit
	r1cs := millerUniform.CreateStepCircuit()

	// Generate witness
	millerUniform.GenerateWitness(r1cs)

	// // Run a standard Miller loop using gnark and compare outputs
	// P_arr := []bn254.G1Affine{P}
	// Q_arr := []bn254.G2Affine{Q}
	// millerResult := bn254.MillerLoop(P_arr, Q_arr)

	// var result_from_witness bn254.E12
	// result_from_witness.Set(&millerUniform.Miller_step_circuit.fOut[2])

	// equal := millerResult.Equal(&result_from_witness)
	// if !equal {
	// 	t.Error("Mismatch between GNARK MillerLoop and witness result from MillerUniformCircuit")
	// } else {
	// 	t.Log("Witness result matches GNARK MillerLoop output")
	// }
}

// func TestMillerStepCircuitSingleStep(t *testing.T) {
// 	_, _, g1GenAff, g2GenAff := bn254.Generators()

// 	var P bn254.G1Affine
// 	var Q bn254.G2Affine

// 	scalar, _ := rand.Int(rand.Reader, bn254_fr.Modulus())
// 	P.ScalarMultiplication(&g1GenAff, scalar)
// 	Q.ScalarMultiplication(&g2GenAff, scalar)

// 	// Compute negQ
// 	var negQ bn254.G2Affine
// 	negQ.X = Q.X
// 	negQ.Y.A1.Neg(&Q.Y.A1)
// 	negQ.Y.A0.Neg(&Q.Y.A0)

// 	// // Prepare FIn and Rin
// 	var FIn bn254.E12
// 	FIn.SetOne()
// 	Rin := ToProjective_fn(&Q)

// 	// Choose bit = 1
// 	bit := 1

// 	// Call the integrated Miller step function
// 	Rout, f1, f2, f3 := MillerLoopStepIntegrated_fn(&Rin, &Q, &negQ, &P, &FIn, bit)

// 	var circuit MillerStepCircuit
// 	r1cs, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)

// 	// Build the circuit
// 	stepCircuit := MillerStepCircuit{
// 		FIn:  field_tower.FromE12(&FIn),
// 		P:    groups.AffineFromG1Affine(&P),
// 		Q:    groups.G2AffineFromBNG2Affine(&Q),
// 		NegQ: groups.G2AffineFromBNG2Affine(&negQ),
// 		Rin:  G2ProjectiveFromBNG2Projective(&Rin),
// 		Rout: G2ProjectiveFromBNG2Projective(&Rout),
// 		Bit:  bit,

// 		FOut: [3]field_tower.Fp12{
// 			field_tower.FromE12(&f1),
// 			field_tower.FromE12(&f2),
// 			field_tower.FromE12(&f3),
// 		},

// 		fIn:  FIn,
// 		p:    P,
// 		rin:  Rin,
// 		q:    Q,
// 		negQ: negQ,
// 		rout: Rout,
// 		bit:  bit,
// 		fOut: [3]bn254.E12{f1, f2, f3},
// 	}

// 	stepCircuit.GenerateWitness(r1cs)

// 	// // Validate result using gnark backend (optional sanity check)
// 	// P_arr := []bn254.G1Affine{P}
// 	// Q_arr := []bn254.G2Affine{Q}
// 	// expected := bn254.MillerLoop(P_arr, Q_arr)

// 	// // Compare with computed f3 only for sanity
// 	// var computed bn254.E12
// 	// computed.Set(&stepCircuit.fOut[2])

// 	// if !expected.Equal(&computed) {
// 	// 	t.Error("MillerStepCircuit test failed: output mismatch with MillerLoop result (single step check)")
// 	// } else {
// 	// 	t.Log("MillerStepCircuit test passed: output matches MillerLoop result")
// 	// }
// }
