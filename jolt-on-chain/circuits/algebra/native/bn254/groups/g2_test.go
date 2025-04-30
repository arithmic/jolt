package g1ops

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	fp2 "github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/field_tower"
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
	fmt.Printf("Circuit compiled in: %s\n\n", duration)

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
	fmt.Printf("Witness generated in: %s\n\n", duration_witness)
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
	fmt.Printf("Circuit compiled in: %s\n\n", duration)

	fmt.Println("number of constraints of G2Neg", r1cs.GetNbConstraints())

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

	_, err_1 := r1cs.Solve(witness)
	if err_1 != nil {
		fmt.Println("Error solving the r1cs", err_1)
		return
	}
	duration_witness := time.Since(start_witness)
	fmt.Printf("Witness generated in: %s\n\n", duration_witness)
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
	fmt.Printf("Circuit compiled in: %s\n\n", duration)

	fmt.Println("number of constraints of G2Sub", r1cs.GetNbConstraints())

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

	_, err_1 := r1cs.Solve(witness)
	if err_1 != nil {
		fmt.Println("Error solving the r1cs", err_1)
		return
	}
	duration_witness := time.Since(start_witness)
	fmt.Printf("Witness generated in: %s\n\n", duration_witness)
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
	fmt.Printf("Circuit compiled in: %s\n\n", duration)

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
	fmt.Printf("Witness generated in: %s\n\n", duration_witness)
}

type G2DoubleNCircuit struct {
	A, B G2Affine
	n    int
}

func (circuit *G2DoubleNCircuit) Define(api frontend.API) error {
	e := NewG2(api)
	const fixedN = 10
	expected := e.G2DoubleN(&circuit.A, fixedN)
	e.AssertIsEqual(expected, &circuit.B)

	return nil
}

func TestCircuitG2DoubleN(t *testing.T) {
	var circuit G2DoubleNCircuit
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n\n", duration)

	fmt.Println("number of constraints of G2DoubleN for n = 10:", r1cs.GetNbConstraints())

	_, in1 := randomG1G2Affines()
	var res bn254.G2Affine
	res = in1
	for i := 0; i < 10; i++ {
		res.Double(&res)
	}
	assignment := G2DoubleNCircuit{
		A: FromBNG2Affine(&in1),
		B: FromBNG2Affine(&res),
		n: 10,
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
	fmt.Printf("Witness generated in: %s\n\n", duration_witness)
}

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
	fmt.Printf("Circuit compiled in: %s\n\n", duration)

	fmt.Println("number of constraints of G2DoubleAndAdd", r1cs.GetNbConstraints())

	_, _, _, in1 := bn254.Generators()
	var in2 bn254.G2Affine
	in2.Double(&in1)

	var res bn254.G2Affine
	res.Double(&in1).
		Add(&res, &in2)

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
	fmt.Printf("Witness generated in: %s\n\n", duration_witness)
}

type G2scalarMulBySeedCircuit struct {
	In1 G2Affine
	Res G2Affine
}

func (circuit *G2scalarMulBySeedCircuit) Define(api frontend.API) error {
	g2 := NewG2(api)
	res := g2.G2scalarMulBySeed(&circuit.In1)
	g2.AssertIsEqual(res, &circuit.Res)
	return nil
}

func TestCircuitG2scalarMulBySeedCircuit(t *testing.T) {
	var circuit G2scalarMulBySeedCircuit
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n\n", duration)

	fmt.Println("number of constraints of G2scalarMulBySeed", r1cs.GetNbConstraints())

	_, in1 := randomG1G2Affines()
	var res bn254.G2Affine

	x0, _ := new(big.Int).SetString("4965661367192848881", 10)
	res.ScalarMultiplication(&in1, x0)

	assignment := G2scalarMulBySeedCircuit{
		In1: FromBNG2Affine(&in1),
		Res: FromBNG2Affine(&res),
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
	fmt.Printf("Witness generated in: %s\n\n", duration_witness)
}

type G2endomorphismCircuit struct {
	In1 G2Affine
}

func (c *G2endomorphismCircuit) Define(api frontend.API) error {
	g2 := NewG2(api)
	w, _ := new(big.Int).SetString("21888242871839275220042445260109153167277707414472061641714758635765020556616", 10)
	w, _ = api.ConstantValue(w)
	res1 := g2.phi(&c.In1, w)

	u0, _ := new(big.Int).SetString("21575463638280843010398324269430826099269044274347216827212613867836435027261", 10)
	u0, _ = api.ConstantValue(u0)

	u1, _ := new(big.Int).SetString("10307601595873709700152284273816112264069230130616436755625194854815875713954", 10)
	u1, _ = api.ConstantValue(u1)

	v0, _ := new(big.Int).SetString("2821565182194536844548159561693502659359617185244120367078079554186484126554", 10)
	v0, _ = api.ConstantValue(v0)

	v1, _ := new(big.Int).SetString("3505843767911556378687030309984248845540243509899259641013678093033130930403", 10)
	v1, _ = api.ConstantValue(v1)

	res2 := g2.psi(&c.In1, fp2.Fp2{A0: u0, A1: u1}, fp2.Fp2{A0: v0, A1: v1})
	res2 = g2.psi(res2, fp2.Fp2{A0: u0, A1: u1}, fp2.Fp2{A0: v0, A1: v1})
	g2.AssertIsEqual(res1, res2)
	return nil
}

func TestEndomorphismG2TestSolve(t *testing.T) {
	var circuit G2endomorphismCircuit
	start := time.Now()
	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Error compiling circuit: %s", err)
	}
	duration := time.Since(start)
	fmt.Printf("Circuit compiled in: %s\n\n", duration)

	fmt.Println("number of constraints of G2scalarMulBySeed", r1cs.GetNbConstraints())

	_, in1 := randomG1G2Affines()

	assignment := G2endomorphismCircuit{
		In1: FromBNG2Affine(&in1),
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
	fmt.Printf("Witness generated in: %s\n\n", duration_witness)
}
