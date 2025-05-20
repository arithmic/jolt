package pcs

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	constraint "github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/field_tower"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/groups"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254Fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
	"math/big"
	"os"
	"strconv"
	"testing"
	"time"
)

type G1ScalarUniformCircuit struct {
	In  groups.G1Projective `gnark:",public"`
	Exp frontend.Variable   `gnark:",public"`
	Acc groups.G1Projective
}

func (circuit *G1ScalarUniformCircuit) Define(api frontend.API) error {
	groupAPI := &groups.G1API{Api: api}
	groupAPI.Add(&circuit.Acc, groupAPI.ScalarMul(&circuit.In, &circuit.Exp))
	return nil
}

type GTUniformCircuit struct {
	Out field_tower.Fp12 `gnark:",public"`
	In  field_tower.Fp12 `gnark:",public"`
	Acc field_tower.Fp12
}

func (circuit *GTUniformCircuit) Define(api frontend.API) error {
	gtAPI := field_tower.NewExt12(api)
	mul := gtAPI.Mul(&circuit.Acc, &circuit.In)
	gtAPI.AssertIsEqual(&circuit.Out, mul)
	return nil
}

type SingleGTUniformCircuit struct {
	In  field_tower.Fp12
	Acc field_tower.Fp12
	Bit frontend.Variable
	Out field_tower.Fp12 `gnark:",public"`
}

func (circuit *SingleGTUniformCircuit) Define(api frontend.API) error {
	gtAPI := field_tower.NewExt12(api)
	accSquare := gtAPI.Square(&circuit.Acc)
	accSquareMulIn := gtAPI.Mul(accSquare, &circuit.In)
	expectedOut := gtAPI.Select2(circuit.Bit, accSquareMulIn, accSquare)
	gtAPI.AssertIsEqual(&circuit.Out, expectedOut)
	return nil
}

func TestUniformSingleGTExp(t *testing.T) {
	var a, c bn254.E12
	var b bn254Fp.Element
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()

	var circuit SingleGTUniformCircuit
	start := time.Now()
	uniformConstraints, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	circuitJson, _ := json.MarshalIndent(uniformConstraints, "", "  ")
	_ = os.WriteFile("r1cs.json", circuitJson, 0644)

	duration := time.Since(start)
	fmt.Printf("Circuit compilation time  : %s\n", duration)
	_, aCount, bCount, cCount := ExtractConstraints(uniformConstraints)
	println("aCount:", aCount, "bCount:", bCount, "cCount:", cCount)

	var frZero, frOne fr.Element
	frZero.SetZero()
	frOne.SetOne()

	var frBigInt big.Int
	b.BigInt(&frBigInt)
	bit := frBigInt.Bit(253)
	c.Exp(a, &frBigInt)

	var out bn254.E12
	out.SetOne()

	var one field_tower.Fp12
	one = field_tower.FromE12(&out)

	out = computeOut(a, out, bit)

	in := field_tower.FromE12(&a)
	assignment := &SingleGTUniformCircuit{
		In:  in,
		Acc: one,
		Bit: bit,
		Out: field_tower.FromE12(&out),
	}

	start = time.Now()
	witness, _ := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())

	wit, _ := uniformConstraints.Solve(witness)
	z := wit.(*cs.R1CSSolution).W

	var extendZ fr.Vector
	zLen := len(z)
	println("zLen:", zLen)
	for idx := 0; idx < zLen; idx++ {
		extendZ = append(extendZ, z[idx])
	}

	for idx := 0; idx < 253; idx++ {
		bit = frBigInt.Bit(253 - idx - 1)
		out = computeOut(a, out, bit)

		Acc := field_tower.Fp12{A0: field_tower.Fp6{A0: field_tower.Fp2{A0: z[1], A1: z[2]}, A1: field_tower.Fp2{A0: z[3], A1: z[4]}, A2: field_tower.Fp2{A0: z[5], A1: z[6]}}, A1: field_tower.Fp6{A0: field_tower.Fp2{A0: z[7], A1: z[8]}, A1: field_tower.Fp2{A0: z[9], A1: z[10]}, A2: field_tower.Fp2{A0: z[11], A1: z[12]}}}

		assignment := &SingleGTUniformCircuit{
			In:  field_tower.FromE12(&a),
			Acc: Acc,
			Bit: bit,
			Out: field_tower.FromE12(&out),
		}

		witness, _ := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
		wit, _ := uniformConstraints.Solve(witness)
		z = wit.(*cs.R1CSSolution).W
		//fmt.Println(z)
		for idx := 0; idx < len(z); idx++ {
			extendZ = append(extendZ, z[idx])
		}
	}
	duration = time.Since(start)
	fmt.Printf("Witness generation time 2 : %s\n", duration)
	//
	//fmt.Printf("exp res is  : %d\n", c)
	//
	//actualResult := field_tower.Fp12{A0: field_tower.Fp6{A0: field_tower.Fp2{A0: z[1], A1: z[2]}, A1: field_tower.Fp2{A0: z[3], A1: z[4]}, A2: field_tower.Fp2{A0: z[5], A1: z[6]}}, A1: field_tower.Fp6{A0: field_tower.Fp2{A0: z[7], A1: z[8]}, A1: field_tower.Fp2{A0: z[9], A1: z[10]}, A2: field_tower.Fp2{A0: z[11], A1: z[12]}}}
	//fmt.Printf("actual res is  : %s\n", actualResult)

	fmt.Println("number of constraints ", uniformConstraints.GetNbConstraints())

}

func TestUniformGTExp(t *testing.T) {
	var a [100]bn254.E12
	var b [100]bn254Fp.Element
	var frBigInt [100]big.Int
	for idx := 0; idx < 100; idx++ {
		_, _ = a[idx].SetRandom()
		_, _ = b[idx].SetRandom()
		b[idx].BigInt(&frBigInt[idx])
	}

	var gtUniformCircuit GTUniformCircuit
	var singleGTUniformCircuit SingleGTUniformCircuit

	start := time.Now()
	gtUniformConstraints, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &gtUniformCircuit)
	duration := time.Since(start)
	fmt.Printf("GT Circuit compilation time  : %s\n", duration)

	_, aCount, bCount, cCount := ExtractConstraints(gtUniformConstraints)
	println("GT Uniform Circuit", "aCount:", aCount, "bCount:", bCount, "cCount:", cCount)

	start = time.Now()
	singleGTUniformConstraints, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &singleGTUniformCircuit)
	duration = time.Since(start)
	fmt.Printf("Single Gt Circuit compilation time : %s\n", duration)

	_, aCount, bCount, cCount = ExtractConstraints(singleGTUniformConstraints)
	println("Single GT Uniform Circuit", "aCount:", aCount, "bCount:", bCount, "cCount:", cCount)

	var frZero, frOne fr.Element
	frZero.SetZero()
	frOne.SetOne()

	var bn254One bn254.E12
	bn254One.SetOne()
	var one field_tower.Fp12
	one = field_tower.FromE12(&bn254One)

	var gtExtendZ fr.Vector

	var singleGTExtendZ fr.Vector
	var gtZ fr.Vector

	var finalResult bn254.E12
	finalResult.SetOne()

	for i := 0; i < 100; i++ {
		var exp bn254.E12
		exp.Exp(a[i], &frBigInt[i])
		finalResult.Mul(&finalResult, &exp)
	}

	var gtOut bn254.E12
	gtOut.SetOne()
	outerStart := time.Now()
	for outerIdx := 0; outerIdx < 100; outerIdx++ {
		var out bn254.E12
		out.SetOne()
		bit := frBigInt[outerIdx].Bit(253)
		out = computeOut(a[outerIdx], out, bit)

		singleGTAssignment := &SingleGTUniformCircuit{
			In:  field_tower.FromE12(&a[outerIdx]),
			Acc: one,
			Bit: bit,
			Out: field_tower.FromE12(&out),
		}

		innerStart := time.Now()
		singleGTWitnessObject, _ := frontend.NewWitness(singleGTAssignment, ecc.GRUMPKIN.ScalarField())
		singleGTWitness, _ := singleGTUniformConstraints.Solve(singleGTWitnessObject)
		singleGTZ := singleGTWitness.(*cs.R1CSSolution).W
		zLen := len(singleGTZ)

		for idx := 0; idx < zLen; idx++ {
			singleGTExtendZ = append(singleGTExtendZ, singleGTZ[idx])
		}

		for innerIdx := 1; innerIdx < 254; innerIdx++ {
			bit = frBigInt[outerIdx].Bit(253 - innerIdx)
			out = computeOut(a[outerIdx], out, bit)

			Acc := field_tower.Fp12{A0: field_tower.Fp6{A0: field_tower.Fp2{A0: singleGTZ[1], A1: singleGTZ[2]}, A1: field_tower.Fp2{A0: singleGTZ[3], A1: singleGTZ[4]}, A2: field_tower.Fp2{A0: singleGTZ[5], A1: singleGTZ[6]}}, A1: field_tower.Fp6{A0: field_tower.Fp2{A0: singleGTZ[7], A1: singleGTZ[8]}, A1: field_tower.Fp2{A0: singleGTZ[9], A1: singleGTZ[10]}, A2: field_tower.Fp2{A0: singleGTZ[11], A1: singleGTZ[12]}}}

			singleGTAssignment = &SingleGTUniformCircuit{
				In:  field_tower.FromE12(&a[outerIdx]),
				Acc: Acc,
				Bit: bit,
				Out: field_tower.FromE12(&out),
			}

			singleGTWitnessObject, _ = frontend.NewWitness(singleGTAssignment, ecc.GRUMPKIN.ScalarField())
			singleGTWitness, _ = singleGTUniformConstraints.Solve(singleGTWitnessObject)
			singleGTZ = singleGTWitness.(*cs.R1CSSolution).W
			for idx := 0; idx < len(singleGTZ); idx++ {
				singleGTExtendZ = append(singleGTExtendZ, singleGTZ[idx])
			}
		}

		expResult := field_tower.Fp12{A0: field_tower.Fp6{A0: field_tower.Fp2{A0: singleGTZ[1], A1: singleGTZ[2]}, A1: field_tower.Fp2{A0: singleGTZ[3], A1: singleGTZ[4]}, A2: field_tower.Fp2{A0: singleGTZ[5], A1: singleGTZ[6]}}, A1: field_tower.Fp6{A0: field_tower.Fp2{A0: singleGTZ[7], A1: singleGTZ[8]}, A1: field_tower.Fp2{A0: singleGTZ[9], A1: singleGTZ[10]}, A2: field_tower.Fp2{A0: singleGTZ[11], A1: singleGTZ[12]}}}

		var acc field_tower.Fp12

		if outerIdx == 0 {
			acc = one
		} else {
			acc = field_tower.Fp12{A0: field_tower.Fp6{A0: field_tower.Fp2{A0: gtZ[1], A1: gtZ[2]}, A1: field_tower.Fp2{A0: gtZ[3], A1: gtZ[4]}, A2: field_tower.Fp2{A0: gtZ[5], A1: gtZ[6]}}, A1: field_tower.Fp6{A0: field_tower.Fp2{A0: gtZ[7], A1: gtZ[8]}, A1: field_tower.Fp2{A0: gtZ[9], A1: gtZ[10]}, A2: field_tower.Fp2{A0: gtZ[11], A1: gtZ[12]}}}
		}

		expResultE12 := bn254.E12{C0: bn254.E6{B0: bn254.E2{A0: bn254Fp.Element(singleGTZ[1]), A1: bn254Fp.Element(singleGTZ[2])}, B1: bn254.E2{A0: bn254Fp.Element(singleGTZ[3]), A1: bn254Fp.Element(singleGTZ[4])}, B2: bn254.E2{A0: bn254Fp.Element(singleGTZ[5]), A1: bn254Fp.Element(singleGTZ[6])}}, C1: bn254.E6{B0: bn254.E2{A0: bn254Fp.Element(singleGTZ[7]), A1: bn254Fp.Element(singleGTZ[8])}, B1: bn254.E2{A0: bn254Fp.Element(singleGTZ[9]), A1: bn254Fp.Element(singleGTZ[10])}, B2: bn254.E2{A0: bn254Fp.Element(singleGTZ[11]), A1: bn254Fp.Element(singleGTZ[12])}}}

		gtOut = *computeOut2(gtOut, expResultE12)
		gtAssignment := &GTUniformCircuit{
			In:  expResult,
			Out: field_tower.FromE12(&gtOut),
			Acc: acc,
		}

		gtWitnessObject, _ := frontend.NewWitness(gtAssignment, ecc.GRUMPKIN.ScalarField())

		gtWitness, _ := gtUniformConstraints.Solve(gtWitnessObject)
		gtZ = gtWitness.(*cs.R1CSSolution).W
		for idx := 0; idx < len(gtZ); idx++ {
			gtExtendZ = append(gtExtendZ, gtZ[idx])
		}
		innerDuration := time.Since(innerStart)
		fmt.Printf("Witness generation time : %s\n", innerDuration)
	}
	actualResult := field_tower.Fp12{A0: field_tower.Fp6{A0: field_tower.Fp2{A0: gtZ[1], A1: gtZ[2]}, A1: field_tower.Fp2{A0: gtZ[3], A1: gtZ[4]}, A2: field_tower.Fp2{A0: gtZ[5], A1: gtZ[6]}}, A1: field_tower.Fp6{A0: field_tower.Fp2{A0: gtZ[7], A1: gtZ[8]}, A1: field_tower.Fp2{A0: gtZ[9], A1: gtZ[10]}, A2: field_tower.Fp2{A0: gtZ[11], A1: gtZ[12]}}}
	outerDuration := time.Since(outerStart)
	fmt.Printf("Gt witness generation time : %s\n", outerDuration)
	fmt.Println("Expected Result is ", finalResult)
	fmt.Println("Actual Result is ", actualResult)
	//fmt.Println("number of constraints ", gtUniformConstraints.GetNbConstraints())
}

func computeOut(a bn254.E12, acc bn254.E12, bit uint) bn254.E12 {
	acc = *acc.Square(&acc)
	if bit == 1 {
		acc = *acc.Mul(&a, &acc)
	}
	return acc
}
func computeOut2(out bn254.E12, exp bn254.E12) *bn254.E12 {
	var res bn254.E12
	res.Mul(&out, &exp)
	return &res
}

func TestUniformG1Scalar(t *testing.T) {
	var a [250]bn254.G1Affine
	for i := 0; i < 250; i++ {
		a[i] = groups.RandomG1Affine()
	}

	var exp [250]fr.Element
	for i := 0; i < 250; i++ {
		b_big, _ := rand.Int(rand.Reader, fp.Modulus())
		exp[i].SetBigInt(b_big)
	}

	var circuit G1ScalarUniformCircuit
	start := time.Now()
	uniformConstraints, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	duration := time.Since(start)

	var zero, one fr.Element
	zero.SetZero()
	one.SetOne()

	assignment := &G1ScalarUniformCircuit{
		In: groups.FromG1Affine(&a[0]),
		Acc: groups.G1Projective{
			X: zero,
			Y: one,
			Z: zero,
		},
		Exp: exp[0],
	}

	start = time.Now()

	witness, _ := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
	wit, _ := uniformConstraints.Solve(witness)
	z := wit.(*cs.R1CSSolution).W

	var extendZ fr.Vector

	for idx := 0; idx < len(z); idx++ {
		extendZ = append(extendZ, z[idx])
	}

	for idx := 0; idx < 250-1; idx++ {
		zLen := len(z)
		var Acc = groups.G1Projective{X: z[zLen-3], Y: z[zLen-3], Z: z[zLen-3]}
		assignment := &G1ScalarUniformCircuit{
			In:  groups.FromG1Affine(&a[idx+1]),
			Acc: Acc,
			Exp: exp[idx+1],
		}

		witness, _ := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
		wit, _ := uniformConstraints.Solve(witness)
		z = wit.(*cs.R1CSSolution).W

		for idx := 0; idx < len(z); idx++ {
			extendZ = append(extendZ, z[idx])
		}

	}
	duration = time.Since(start)
	fmt.Printf("Witness generation time 2 : %s\n", duration)

	//fmt.Printf("extendZ: %v\n", extendZ)
	if err != nil {
		fmt.Println("Failed to generated witness", err)
		return
	}

	fmt.Println("number of constraints ", uniformConstraints.GetNbConstraints())

}

type Constraint struct {
	A map[string]string
	B map[string]string
	C map[string]string
}

func PrettyPrintConstraints(constraints []Constraint) {
	bytes, err := json.MarshalIndent(constraints, "", "  ")
	if err != nil {
		fmt.Println("Error while pretty printing:", err)
		return
	}
	fmt.Println(string(bytes))
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
