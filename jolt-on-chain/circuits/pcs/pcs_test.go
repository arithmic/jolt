package pcs

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	constraint "github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/uniform"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254Fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
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
	expectedOut := gtAPI.Select(circuit.Bit, accSquareMulIn, accSquare)
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

// func gTExpWitness(base bn254.E12, exp big.Int, constraintsStep *constraint.ConstraintSystem, ch chan fr.Vector) {
func gTExpWitness(base bn254.E12, exp big.Int, constraintsStep *constraint.ConstraintSystem) fr.Vector {
	var acc, out bn254.E12
	acc.SetOne()
	out.SetOne()

	var witness fr.Vector
	var witnessStep fr.Vector

	// var circuitStep SingleGTUniformCircuit
	// constraintsStep, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuitStep)

	for idx := 0; idx < 254; idx++ {
		bit := exp.Bit(253 - idx)
		acc = out
		out = computeOut(base, acc, bit)

		circuitStep := SingleGTUniformCircuit{
			In:  field_tower.FromE12(&base),
			Acc: field_tower.FromE12(&acc),
			Bit: bit,
			Out: field_tower.FromE12(&out),
		}

		w, _ := frontend.NewWitness(&circuitStep, ecc.GRUMPKIN.ScalarField())
		wSolved, err := (*constraintsStep).Solve(w)
		if err != nil {
			fmt.Println(err)
		}
		witnessStep = wSolved.(*cs.R1CSSolution).W
		for idx := 0; idx < len(witnessStep); idx++ {
			witness = append(witness, witnessStep[idx])
		}
	}

	//ch <- witness
	return witness
}

type indexedResult struct {
	idx int
	vec fr.Vector
}

func gTAccWitness(in bn254.E12, acc bn254.E12, out bn254.E12, constraintsStep *constraint.ConstraintSystem, ch chan fr.Vector) {
	var witness fr.Vector
	// fmt.Println("out = ", out)

	circuitStep := GTUniformCircuit{
		Out: field_tower.FromE12(&out),
		In:  field_tower.FromE12(&in),
		Acc: field_tower.FromE12(&acc),
	}

	w, _ := frontend.NewWitness(&circuitStep, ecc.GRUMPKIN.ScalarField())
	wSolved, _ := (*constraintsStep).Solve(w)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	witness = wSolved.(*cs.R1CSSolution).W
	// fmt.Println("Witness = ", witness[1])
	ch <- witness
}

// func TestUniformGTMSEParallel(t *testing.T) {
// 	var a [100]bn254.E12
// 	var b [100]bn254Fp.Element
// 	var frBigInt [100]big.Int
// 	for idx := 0; idx < 100; idx++ {
// 		_, _ = a[idx].SetRandom()
// 		_, _ = b[idx].SetRandom()
// 		b[idx].BigInt(&frBigInt[idx])
// 	}

// 	var witnessGTExp fr.Vector
// 	var gTExpResult []bn254.E12
// 	ch := make(chan fr.Vector, 100)

// 	var circuitStep SingleGTUniformCircuit
// 	constraintsStep, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuitStep)

// 	// var circuitStep GTUniformCircuit
// 	// constraintsStep, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuitStep)

// 	start := time.Now()

// 	for outerIdx := 0; outerIdx < 100; outerIdx++ {
// 		go gTExpWitness(a[outerIdx], frBigInt[outerIdx], &constraintsStep, ch)
// 	}

// 	for outerIdx := 0; outerIdx < 100; outerIdx++ {
// 		w := <-ch
// 		idx := len(w) - 152
// 		computedResult := bn254.E12{C0: bn254.E6{B0: bn254.E2{A0: bn254Fp.Element(w[idx]), A1: bn254Fp.Element(w[idx+1])}, B1: bn254.E2{A0: bn254Fp.Element(w[idx+2]), A1: bn254Fp.Element(w[idx+3])}, B2: bn254.E2{A0: bn254Fp.Element(w[idx+4]), A1: bn254Fp.Element(w[idx+5])}}, C1: bn254.E6{B0: bn254.E2{A0: bn254Fp.Element(w[idx+6]), A1: bn254Fp.Element(w[idx+7])}, B1: bn254.E2{A0: bn254Fp.Element(w[idx+8]), A1: bn254Fp.Element(w[idx+9])}, B2: bn254.E2{A0: bn254Fp.Element(w[idx+10]), A1: bn254Fp.Element(w[idx+11])}}}

// 		gTExpResult = append(gTExpResult, computedResult)

// 		for i := 0; i < len(w); i++ {
// 			witnessGTExp = append(witnessGTExp, w[i])
// 		}
// 	}

// 	var acc, out [100]bn254.E12
// 	acc[0].SetOne()
// 	out[0].SetOne()

// 	for i := 0; i < 10; i++ {
// 		acc[i] = out[i]
// 		fmt.Println("acc[i] = ", acc[i])
// 		fmt.Println("gTExpResult[i] = ", gTExpResult[i])

// 		out[i] = *computeOut2(acc[i], gTExpResult[i])
// 	}

// 	var circuitStep_1 GTUniformCircuit
// 	constraintsStep, _ = frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuitStep_1)

// 	ch_1 := make(chan fr.Vector, 100)

// 	for i := 0; i < 100; i++ {
// 		go gTAccWitness(gTExpResult[i], acc[i], out[i], &constraintsStep, ch_1)
// 	}

// 	// fmt.Println("HERE HERE")

// 	var witnessAcc fr.Vector

// 	for outerIdx := 0; outerIdx < 100; outerIdx++ {
// 		witnessAcc = <-ch_1
// 		// idx := len(w) - 152
// 		// computedResult := bn254.E12{C0: bn254.E6{B0: bn254.E2{A0: bn254Fp.Element(w[idx]), A1: bn254Fp.Element(w[idx+1])}, B1: bn254.E2{A0: bn254Fp.Element(w[idx+2]), A1: bn254Fp.Element(w[idx+3])}, B2: bn254.E2{A0: bn254Fp.Element(w[idx+4]), A1: bn254Fp.Element(w[idx+5])}}, C1: bn254.E6{B0: bn254.E2{A0: bn254Fp.Element(w[idx+6]), A1: bn254Fp.Element(w[idx+7])}, B1: bn254.E2{A0: bn254Fp.Element(w[idx+8]), A1: bn254Fp.Element(w[idx+9])}, B2: bn254.E2{A0: bn254Fp.Element(w[idx+10]), A1: bn254Fp.Element(w[idx+11])}}}

// 		// gTExpResult = append(gTExpResult, computedResult)

// 		for i := 0; i < len(witnessAcc); i++ {
// 			witnessGTExp = append(witnessGTExp, witnessAcc[i])
// 			// fmt.Println(witnessAcc[i])
// 		}
// 	}

// 	fmt.Println("Witness generation time = ", time.Since(start))
// 	fmt.Println()

// 	var finalResult bn254.E12
// 	finalResult.SetOne()
// 	for i := 0; i < 100; i++ {
// 		var exp bn254.E12
// 		exp.Exp(a[i], &frBigInt[i])
// 		finalResult.Mul(&finalResult, &exp)
// 	}

// 	actualResult := field_tower.Fp12{A0: field_tower.Fp6{A0: field_tower.Fp2{A0: witnessAcc[1], A1: witnessAcc[2]}, A1: field_tower.Fp2{A0: witnessAcc[3], A1: witnessAcc[4]}, A2: field_tower.Fp2{A0: witnessAcc[5], A1: witnessAcc[6]}}, A1: field_tower.Fp6{A0: field_tower.Fp2{A0: witnessAcc[7], A1: witnessAcc[8]}, A1: field_tower.Fp2{A0: witnessAcc[9], A1: witnessAcc[10]}, A2: field_tower.Fp2{A0: witnessAcc[11], A1: witnessAcc[12]}}}

// 	fmt.Println("Expected Result is ", finalResult)
// 	fmt.Println()
// 	fmt.Println("Actual Result is ", actualResult)
// }

func TestUniformGTMSEParallel(t *testing.T) {
	var a [100]bn254.E12
	var b [100]bn254Fp.Element
	var frBigInt [100]big.Int
	for idx := 0; idx < 100; idx++ {
		_, _ = a[idx].SetRandom()
		_, _ = b[idx].SetRandom()
		b[idx].BigInt(&frBigInt[idx])
	}

	var witnessGTExp fr.Vector
	var gTExpResult []bn254.E12

	var circuitStep SingleGTUniformCircuit
	constraintsStep, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuitStep)

	start := time.Now()
	var (
		wg      sync.WaitGroup
		results = make([]fr.Vector, 100)
	)

	wg.Add(100)
	for outerIdx := 0; outerIdx < 100; outerIdx++ {
		go func(i int) {
			defer wg.Done()
			results[i] = gTExpWitness(a[i], frBigInt[i], &constraintsStep)
		}(outerIdx)
	}

	wg.Wait()

	for outerIdx := 0; outerIdx < 100; outerIdx++ {
		w := results[outerIdx]
		idx := len(w) - 152
		computedResult := bn254.E12{C0: bn254.E6{B0: bn254.E2{A0: bn254Fp.Element(w[idx]), A1: bn254Fp.Element(w[idx+1])}, B1: bn254.E2{A0: bn254Fp.Element(w[idx+2]), A1: bn254Fp.Element(w[idx+3])}, B2: bn254.E2{A0: bn254Fp.Element(w[idx+4]), A1: bn254Fp.Element(w[idx+5])}}, C1: bn254.E6{B0: bn254.E2{A0: bn254Fp.Element(w[idx+6]), A1: bn254Fp.Element(w[idx+7])}, B1: bn254.E2{A0: bn254Fp.Element(w[idx+8]), A1: bn254Fp.Element(w[idx+9])}, B2: bn254.E2{A0: bn254Fp.Element(w[idx+10]), A1: bn254Fp.Element(w[idx+11])}}}

		gTExpResult = append(gTExpResult, computedResult)

		for i := 0; i < len(w); i++ {
			witnessGTExp = append(witnessGTExp, w[i])
		}
	}

	var acc, out bn254.E12
	acc.SetOne()
	out.SetOne()

	var witnessMSE fr.Vector
	var witnessStep fr.Vector

	var accCircuitStep GTUniformCircuit
	accConstraintsStep, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &accCircuitStep)

	for idx := 0; idx < 100; idx++ {
		acc = out
		out = *computeOut2(acc, gTExpResult[idx])

		accCircuitStep = GTUniformCircuit{
			Out: field_tower.FromE12(&out),
			In:  field_tower.FromE12(&gTExpResult[idx]),
			Acc: field_tower.FromE12(&acc),
		}

		w, _ := frontend.NewWitness(&accCircuitStep, ecc.GRUMPKIN.ScalarField())
		wSolved, _ := accConstraintsStep.Solve(w)
		witnessStep = wSolved.(*cs.R1CSSolution).W
		for idx := 0; idx < len(witnessStep); idx++ {
			witnessMSE = append(witnessMSE, witnessStep[idx])
		}
	}

	fmt.Println("Witness generation time = ", time.Since(start))
	fmt.Println()

	var finalResult bn254.E12
	finalResult.SetOne()
	for i := 0; i < 100; i++ {
		var exp bn254.E12
		exp.Exp(a[i], &frBigInt[i])
		finalResult.Mul(&finalResult, &exp)
	}

	actualResult := field_tower.Fp12{A0: field_tower.Fp6{A0: field_tower.Fp2{A0: witnessStep[1], A1: witnessStep[2]}, A1: field_tower.Fp2{A0: witnessStep[3], A1: witnessStep[4]}, A2: field_tower.Fp2{A0: witnessStep[5], A1: witnessStep[6]}}, A1: field_tower.Fp6{A0: field_tower.Fp2{A0: witnessStep[7], A1: witnessStep[8]}, A1: field_tower.Fp2{A0: witnessStep[9], A1: witnessStep[10]}, A2: field_tower.Fp2{A0: witnessStep[11], A1: witnessStep[12]}}}

	fmt.Println("Expected Result is ", finalResult)
	fmt.Println()
	fmt.Println("Actual Result is ", actualResult)
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

func TestCircuitdory(t *testing.T) {

	in1, in2 := groups.RandomG1G2Affines()
	// in11, in22 := groups.RandomG1G2Affines()
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()

	n := 5
	alpha := make([]fr.Element, n)
	beta := make([]fr.Element, n)
	chi := make([]fr.Element, n)

	for i := 0; i < n; i++ {
		_, _ = alpha[i].SetRandom()
		_, _ = beta[i].SetRandom()
		_, _ = chi[i].SetRandom()
	}

	C_Plus_arr := make([]bn254.E12, n)
	C_Plus := make([]GT, n)

	C_Minus := make([]GT, n)
	C_Minus_arr := make([]bn254.E12, n)

	D1_L_arr := make([]bn254.E12, n)
	D1_L := make([]GT, n)

	D1_R_arr := make([]bn254.E12, n)
	D1_R := make([]GT, n)

	D2_L_arr := make([]bn254.E12, n)
	D2_L := make([]GT, n)

	D2_R_arr := make([]bn254.E12, n)
	D2_R := make([]GT, n)

	Delta1_L_arr := make([]bn254.E12, n)
	Delta1_L := make([]GT, n)

	Delta1_R_arr := make([]bn254.E12, n)
	Delta1_R := make([]GT, n)

	Delta2_L_arr := make([]bn254.E12, n)
	Delta2_L := make([]GT, n)

	Delta2_R_arr := make([]bn254.E12, n)
	Delta2_R := make([]GT, n)

	E1_Beta := make([]groups.G1Projective, n)
	E1_PLUS := make([]groups.G1Projective, n)
	E1_MINUS := make([]groups.G1Projective, n)
	E2_Beta := make([]groups.G2Projective, n)
	E2_PLUS := make([]groups.G2Projective, n)
	E2_MINUS := make([]groups.G2Projective, n)

	for i := 0; i < n; i++ {
		_, _ = C_Plus_arr[i].SetRandom()
		C_Plus[i] = field_tower.FromE12(&C_Plus_arr[i])
		_, _ = C_Minus_arr[i].SetRandom()
		C_Minus[i] = field_tower.FromE12(&C_Minus_arr[i])
		_, _ = D1_L_arr[i].SetRandom()
		D1_L[i] = field_tower.FromE12(&D1_L_arr[i])

		_, _ = D1_R_arr[i].SetRandom()
		D1_R[i] = field_tower.FromE12(&D1_R_arr[i])

		_, _ = D2_L_arr[i].SetRandom()
		D2_L[i] = field_tower.FromE12(&D2_L_arr[i])
		_, _ = D2_R_arr[i].SetRandom()
		D2_R[i] = field_tower.FromE12(&D2_R_arr[i])

		_, _ = Delta1_L_arr[i].SetRandom()
		Delta1_L[i] = field_tower.FromE12(&Delta1_L_arr[i])
		_, _ = Delta1_R_arr[i].SetRandom()
		Delta1_R[i] = field_tower.FromE12(&Delta1_R_arr[i])
		_, _ = Delta2_L_arr[i].SetRandom()
		Delta2_L[i] = field_tower.FromE12(&Delta2_L_arr[i])
		_, _ = Delta2_R_arr[i].SetRandom()
		Delta2_R[i] = field_tower.FromE12(&Delta2_R_arr[i])

		in1, in2 = groups.RandomG1G2Affines()
		E1_Beta[i] = groups.FromG1Affine(&in1)
		E2_Beta[i] = groups.FromBNG2Affine(&in2)

		in1, in2 = groups.RandomG1G2Affines()
		E1_PLUS[i] = groups.FromG1Affine(&in1)
		E2_PLUS[i] = groups.FromBNG2Affine(&in2)

		in1, in2 = groups.RandomG1G2Affines()
		E1_MINUS[i] = groups.FromG1Affine(&in1)
		E2_MINUS[i] = groups.FromBNG2Affine(&in2)

	}

	dory_Circuit := DoryVerifierUniform{
		C:                field_tower.FromE12(&a),
		D1:               field_tower.FromE12(&b),
		D2:               field_tower.FromE12(&c),
		E1:               groups.FromG1Affine(&in1),
		E2:               groups.FromBNG2Affine(&in2),
		Alpha:            utils.MakeFrontendVariable(alpha),
		Beta:             utils.MakeFrontendVariable(beta),
		Chi:              utils.MakeFrontendVariable(chi),
		C_Plus:           C_Plus,
		C_Minus:          C_Minus,
		D1_L:             D1_L,
		D1_R:             D1_R,
		D2_L:             D2_L,
		D2_R:             D2_R,
		Delta1_L:         Delta1_L,
		Delta1_R:         Delta1_R,
		Delta2_L:         Delta2_L,
		Delta2_R:         Delta2_R,
		E1_Beta:          E1_Beta,
		E1_PLUS:          E1_PLUS,
		E1_MINUS:         E1_MINUS,
		E2_Beta:          E2_Beta,
		E2_PLUS:          E2_PLUS,
		E2_MINUS:         E2_MINUS,
		doryverifierstep: &DoryVerifierStep{},
	}

	dory_R1Cs := dory_Circuit.CreateStepCircuit()
	dory_Circuit.GenerateWitness(dory_R1Cs)

}

func PrintR1CSStatsUniformDory(dory *DoryVerifierUniform) {
	r1csInfo := dory.GetConstraints()

	// generate full witness
	stepCS := dory.CreateStepCircuit()
	witness := dory.GenerateWitness(stepCS)
	numVars := len(witness)

	constraintsPerStep := len(r1csInfo.Constraints)

	fmt.Println("constraintsPerStep :", constraintsPerStep)
	numSteps := int(r1csInfo.NumSteps)
	totalConstraints := numSteps * constraintsPerStep

	rows := totalConstraints
	cols := numVars
	totalEntries := rows * cols

	totalA := int(r1csInfo.ACount) * numSteps
	totalB := int(r1csInfo.BCount) * numSteps
	totalC := int(r1csInfo.CCount) * numSteps

	fmt.Printf("Matrix size: %d rows x %d columns\n", rows, cols)
	fmt.Printf("Constraints: %d\n", totalConstraints)

	fmt.Printf("A non-zero: %d, zero: %d \n", totalA, totalEntries-totalA)
	fmt.Printf("B non-zero: %d, zero: %d \n", totalB, totalEntries-totalB)
	fmt.Printf("C non-zero: %d, zero: %d \n", totalC, totalEntries-totalC)
}

func TestCircuitdoryMatrix(t *testing.T) {

	in1, in2 := groups.RandomG1G2Affines()
	// in11, in22 := groups.RandomG1G2Affines()
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()

	n := 5
	alpha := make([]fr.Element, n)
	beta := make([]fr.Element, n)
	chi := make([]fr.Element, n)

	for i := 0; i < n; i++ {
		_, _ = alpha[i].SetRandom()
		_, _ = beta[i].SetRandom()
		_, _ = chi[i].SetRandom()
	}

	C_Plus_arr := make([]bn254.E12, n)
	C_Plus := make([]GT, n)

	C_Minus := make([]GT, n)
	C_Minus_arr := make([]bn254.E12, n)

	D1_L_arr := make([]bn254.E12, n)
	D1_L := make([]GT, n)

	D1_R_arr := make([]bn254.E12, n)
	D1_R := make([]GT, n)

	D2_L_arr := make([]bn254.E12, n)
	D2_L := make([]GT, n)

	D2_R_arr := make([]bn254.E12, n)
	D2_R := make([]GT, n)

	Delta1_L_arr := make([]bn254.E12, n)
	Delta1_L := make([]GT, n)

	Delta1_R_arr := make([]bn254.E12, n)
	Delta1_R := make([]GT, n)

	Delta2_L_arr := make([]bn254.E12, n)
	Delta2_L := make([]GT, n)

	Delta2_R_arr := make([]bn254.E12, n)
	Delta2_R := make([]GT, n)

	E1_Beta := make([]groups.G1Projective, n)
	E1_PLUS := make([]groups.G1Projective, n)
	E1_MINUS := make([]groups.G1Projective, n)
	E2_Beta := make([]groups.G2Projective, n)
	E2_PLUS := make([]groups.G2Projective, n)
	E2_MINUS := make([]groups.G2Projective, n)

	for i := 0; i < n; i++ {
		_, _ = C_Plus_arr[i].SetRandom()
		C_Plus[i] = field_tower.FromE12(&C_Plus_arr[i])
		_, _ = C_Minus_arr[i].SetRandom()
		C_Minus[i] = field_tower.FromE12(&C_Minus_arr[i])
		_, _ = D1_L_arr[i].SetRandom()
		D1_L[i] = field_tower.FromE12(&D1_L_arr[i])

		_, _ = D1_R_arr[i].SetRandom()
		D1_R[i] = field_tower.FromE12(&D1_R_arr[i])

		_, _ = D2_L_arr[i].SetRandom()
		D2_L[i] = field_tower.FromE12(&D2_L_arr[i])
		_, _ = D2_R_arr[i].SetRandom()
		D2_R[i] = field_tower.FromE12(&D2_R_arr[i])

		_, _ = Delta1_L_arr[i].SetRandom()
		Delta1_L[i] = field_tower.FromE12(&Delta1_L_arr[i])
		_, _ = Delta1_R_arr[i].SetRandom()
		Delta1_R[i] = field_tower.FromE12(&Delta1_R_arr[i])
		_, _ = Delta2_L_arr[i].SetRandom()
		Delta2_L[i] = field_tower.FromE12(&Delta2_L_arr[i])
		_, _ = Delta2_R_arr[i].SetRandom()
		Delta2_R[i] = field_tower.FromE12(&Delta2_R_arr[i])

		in1, in2 = groups.RandomG1G2Affines()
		E1_Beta[i] = groups.FromG1Affine(&in1)
		E2_Beta[i] = groups.FromBNG2Affine(&in2)

		in1, in2 = groups.RandomG1G2Affines()
		E1_PLUS[i] = groups.FromG1Affine(&in1)
		E2_PLUS[i] = groups.FromBNG2Affine(&in2)

		in1, in2 = groups.RandomG1G2Affines()
		E1_MINUS[i] = groups.FromG1Affine(&in1)
		E2_MINUS[i] = groups.FromBNG2Affine(&in2)

	}

	dory_Circuit := DoryVerifierUniform{
		n:                n,
		C:                field_tower.FromE12(&a),
		D1:               field_tower.FromE12(&b),
		D2:               field_tower.FromE12(&c),
		E1:               groups.FromG1Affine(&in1),
		E2:               groups.FromBNG2Affine(&in2),
		Alpha:            utils.MakeFrontendVariable(alpha),
		Beta:             utils.MakeFrontendVariable(beta),
		Chi:              utils.MakeFrontendVariable(chi),
		C_Plus:           C_Plus,
		C_Minus:          C_Minus,
		D1_L:             D1_L,
		D1_R:             D1_R,
		D2_L:             D2_L,
		D2_R:             D2_R,
		Delta1_L:         Delta1_L,
		Delta1_R:         Delta1_R,
		Delta2_L:         Delta2_L,
		Delta2_R:         Delta2_R,
		E1_Beta:          E1_Beta,
		E1_PLUS:          E1_PLUS,
		E1_MINUS:         E1_MINUS,
		E2_Beta:          E2_Beta,
		E2_PLUS:          E2_PLUS,
		E2_MINUS:         E2_MINUS,
		doryverifierstep: &DoryVerifierStep{},
	}

	PrintR1CSStatsUniformDory(&dory_Circuit)
}

func TestDoryPieceWiseUniform(t *testing.T) {
	// Create test data
	n := 17 // number of steps

	// Generate random field elements
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()

	// Generate random scalars with 128-bit alpha, beta, chi
	alpha := make([]fr.Element, n)
	beta := make([]fr.Element, n)
	chi := make([]fr.Element, n)
	s := make([]fr.Element, n)
	r := make([]fr.Element, n)
	var d fr.Element

	for i := 0; i < n; i++ {
		// Generate 128-bit values for alpha, beta, chi, s, r
		alphaBytes := make([]byte, 16) // 16 bytes = 128 bits
		betaBytes := make([]byte, 16)
		chiBytes := make([]byte, 16)
		sBytes := make([]byte, 16)
		rBytes := make([]byte, 16)

		rand.Read(alphaBytes)
		rand.Read(betaBytes)
		rand.Read(chiBytes)
		rand.Read(sBytes)
		rand.Read(rBytes)

		var alphaBig, betaBig, chiBig, sBig, rBig big.Int
		alphaBig.SetBytes(alphaBytes)
		betaBig.SetBytes(betaBytes)
		chiBig.SetBytes(chiBytes)
		sBig.SetBytes(sBytes)
		rBig.SetBytes(rBytes)

		alpha[i].SetBigInt(&alphaBig)
		beta[i].SetBigInt(&betaBig)
		chi[i].SetBigInt(&chiBig)
		s[i].SetBigInt(&sBig)
		r[i].SetBigInt(&rBig)
	}

	// Generate 128-bit value for d
	dBytes := make([]byte, 16)
	rand.Read(dBytes)
	var dBig big.Int
	dBig.SetBytes(dBytes)
	d.SetBigInt(&dBig)

	// Generate random GT elements
	C_Plus := make([]GT, n)
	C_Minus := make([]GT, n)
	D1_L := make([]GT, n)
	D1_R := make([]GT, n)
	D2_L := make([]GT, n)
	D2_R := make([]GT, n)
	Delta1_L := make([]GT, n)
	Delta1_R := make([]GT, n)
	Delta2_L := make([]GT, n)
	Delta2_R := make([]GT, n)

	for i := 0; i < n; i++ {
		var temp bn254.E12
		_, _ = temp.SetRandom()
		C_Plus[i] = field_tower.FromE12(&temp)
		_, _ = temp.SetRandom()
		C_Minus[i] = field_tower.FromE12(&temp)
		_, _ = temp.SetRandom()
		D1_L[i] = field_tower.FromE12(&temp)
		_, _ = temp.SetRandom()
		D1_R[i] = field_tower.FromE12(&temp)
		_, _ = temp.SetRandom()
		D2_L[i] = field_tower.FromE12(&temp)
		_, _ = temp.SetRandom()
		D2_R[i] = field_tower.FromE12(&temp)
		_, _ = temp.SetRandom()
		Delta1_L[i] = field_tower.FromE12(&temp)
		_, _ = temp.SetRandom()
		Delta1_R[i] = field_tower.FromE12(&temp)
		_, _ = temp.SetRandom()
		Delta2_L[i] = field_tower.FromE12(&temp)
		_, _ = temp.SetRandom()
		Delta2_R[i] = field_tower.FromE12(&temp)
	}

	// Generate random group elements
	E1_Beta := make([]groups.G1Projective, n)
	E1_PLUS := make([]groups.G1Projective, n)
	E1_MINUS := make([]groups.G1Projective, n)
	Alpha_Inv_E1_Minus := make([]groups.G1Projective, n)
	E2_Beta := make([]groups.G2Projective, n)
	E2_PLUS := make([]groups.G2Projective, n)
	E2_MINUS := make([]groups.G2Projective, n)
	Alpha_Inv_E2_Minus := make([]groups.G2Projective, n)

	for i := 0; i < n; i++ {
		g1, g2 := groups.RandomG1G2Affines()
		E1_Beta[i] = groups.FromG1Affine(&g1)
		E2_Beta[i] = groups.FromBNG2Affine(&g2)

		g1, g2 = groups.RandomG1G2Affines()
		E1_PLUS[i] = groups.FromG1Affine(&g1)
		E2_PLUS[i] = groups.FromBNG2Affine(&g2)

		g1, g2 = groups.RandomG1G2Affines()
		E1_MINUS[i] = groups.FromG1Affine(&g1)
		E2_MINUS[i] = groups.FromBNG2Affine(&g2)

		g1, g2 = groups.RandomG1G2Affines()
		Alpha_Inv_E1_Minus[i] = groups.FromG1Affine(&g1)
		Alpha_Inv_E2_Minus[i] = groups.FromBNG2Affine(&g2)
	}

	// Generate random points for final step
	g1_gamma, g2_gamma := groups.RandomG1G2Affines()
	g1_d_gamma, g2_d_inv_gamma := groups.RandomG1G2Affines()
	g1_v, g2_v := groups.RandomG1G2Affines()
	g1_e, g2_e := g1_v, g2_v

	// Create the DoryPieceWiseUniform circuit
	circuit := &DoryPieceWiseUniform{
		n:  n,
		C:  field_tower.FromE12(&a),
		D1: field_tower.FromE12(&b),
		D2: field_tower.FromE12(&c),
		E1: groups.FromG1Affine(&g1_e),
		E2: groups.FromBNG2Affine(&g2_e),

		Alpha:    utils.MakeFrontendVariable(alpha),
		Beta:     utils.MakeFrontendVariable(beta),
		Chi:      utils.MakeFrontendVariable(chi),
		C_Plus:   C_Plus,
		C_Minus:  C_Minus,
		D1_L:     D1_L,
		D1_R:     D1_R,
		D2_L:     D2_L,
		D2_R:     D2_R,
		Delta1_L: Delta1_L,
		Delta1_R: Delta1_R,
		Delta2_L: Delta2_L,
		Delta2_R: Delta2_R,

		E1_Beta:            E1_Beta,
		E1_PLUS:            E1_PLUS,
		E1_MINUS:           E1_MINUS,
		Alpha_Inv_E1_Minus: Alpha_Inv_E1_Minus,
		Alpha_Inv_E2_Minus: Alpha_Inv_E2_Minus,
		E2_Beta:            E2_Beta,
		E2_PLUS:            E2_PLUS,
		E2_MINUS:           E2_MINUS,

		g1MultiMul: &uniform.G1MultiMul{
			Alpha:              utils.MakeFrontendVariable(alpha),
			Beta:               utils.MakeFrontendVariable(beta),
			D:                  d,
			E1_Beta:            E1_Beta,
			E1_Plus:            E1_PLUS,
			Alpha_Inv_E1_Minus: Alpha_Inv_E1_Minus,
			Gamma1:             groups.FromG1Affine(&g1_gamma),
			Step:               &uniform.G1MulStep{},
		},
		g2MultiMul: &uniform.G2MultiMul{
			Alpha:              utils.MakeFrontendVariable(alpha),
			Beta:               utils.MakeFrontendVariable(beta),
			D:                  d,
			E2_Beta:            E2_Beta,
			E2_Plus:            E2_PLUS,
			Alpha_Inv_E2_Minus: Alpha_Inv_E2_Minus,
			Gamma2Out:          groups.FromBNG2Affine(&g2_gamma),
			DInvGamma2:         groups.FromBNG2Affine(&g2_d_inv_gamma),
			Step:               &uniform.G2MulStep{},
		},
		doryUniform: &DoryVerifierUniform{
			n:                n,
			C:                field_tower.FromE12(&a),
			D1:               field_tower.FromE12(&b),
			D2:               field_tower.FromE12(&c),
			E1:               groups.FromG1Affine(&g1_e),
			E2:               groups.FromBNG2Affine(&g2_e),
			Alpha:            utils.MakeFrontendVariable(alpha),
			Beta:             utils.MakeFrontendVariable(beta),
			Chi:              utils.MakeFrontendVariable(chi),
			C_Plus:           C_Plus,
			C_Minus:          C_Minus,
			D1_L:             D1_L,
			D1_R:             D1_R,
			D2_L:             D2_L,
			D2_R:             D2_R,
			Delta1_L:         Delta1_L,
			Delta1_R:         Delta1_R,
			Delta2_L:         Delta2_L,
			Delta2_R:         Delta2_R,
			E1_Beta:          E1_Beta,
			E1_PLUS:          E1_PLUS,
			E1_MINUS:         E1_MINUS,
			E2_Beta:          E2_Beta,
			E2_PLUS:          E2_PLUS,
			E2_MINUS:         E2_MINUS,
			doryverifierstep: &DoryVerifierStep{},
		},

		Gamma1:           groups.FromG1Affine(&g1_gamma),
		d_times_Gamma1:   groups.FromG1Affine(&g1_d_gamma),
		Gamma2:           groups.FromBNG2Affine(&g2_gamma),
		dInvTimes_Gamma2: groups.FromBNG2Affine(&g2_d_inv_gamma),
		V1:               groups.FromG1Affine(&g1_v),
		V2:               groups.FromBNG2Affine(&g2_v),

		D: d,
		S: utils.MakeFrontendVariable(s),
		R: utils.MakeFrontendVariable(r),

		finalstep: &DoryVerifierFinalStepUniform{
			C:                field_tower.FromE12(&a),
			D1:               field_tower.FromE12(&b),
			D2:               field_tower.FromE12(&c),
			E1:               groups.FromG1Affine(&g1_e),
			E2:               groups.FromBNG2Affine(&g2_e),
			Chi:              chi,
			Gamma1:           groups.FromG1Affine(&g1_v),
			D_times_Gamma1:   groups.FromG1Affine(&g1_v),
			Gamma2:           groups.FromBNG2Affine(&g2_v),
			DInvTimes_Gamma2: groups.FromBNG2Affine(&g2_v),
			V1:               groups.FromG1Affine(&g1_v),
			V2:               groups.FromBNG2Affine(&g2_v),
			D:                d,
			S:                utils.MakeFrontendVariable(s),
			R:                utils.MakeFrontendVariable(r),
			Alpha:            utils.MakeFrontendVariable(alpha),
			Step: &DoryVerifierFinalStep{
				S:     utils.MakeFrontendVariable(s),
				R:     utils.MakeFrontendVariable(r),
				Alpha: utils.MakeFrontendVariable(alpha),
			},
		},
	}

	// fmt.Println("Starting DoryPieceWiseUniform circuit compilation...")

	// start := time.Now()
	// stepCircuits := circuit.CreateStepCircuits()
	// duration := time.Since(start)

	// fmt.Printf("DoryPieceWiseUniform circuit compilation time: %s\n", duration)
	// fmt.Printf("Number of step circuits created: %d\n", len(stepCircuits))

	// witness := circuit.GenerateWitness(stepCircuits)

	// fmt.Println("len of witness:", len(witness))
	PrintR1CSStatsPiecewiseDory(circuit)

}

func PrintR1CSStatsPiecewiseDory(dory *DoryPieceWiseUniform) {
	r1csInfo := dory.GetConstraints()

	// generate full witness
	stepCS := dory.CreateStepCircuits()
	witness := dory.GenerateWitness(stepCS)
	numVars := len(witness)

	// Accumulate totals
	totalConstraints := 0
	totalA := 0
	totalB := 0
	totalC := 0
	totalSteps := 0

	for idx, sub := range r1csInfo.UniformR1CSes {
		constraintsPerStep := len(sub.Constraints)
		numSteps := int(sub.NumSteps)

		subTotal := constraintsPerStep * numSteps
		fmt.Printf("Subcircuit %d: %d steps, %d constraints/step, total %d constraints\n",
			idx, numSteps, constraintsPerStep, subTotal)

		totalConstraints += subTotal
		totalSteps += numSteps
		totalA += int(sub.ACount) * numSteps
		totalB += int(sub.BCount) * numSteps
		totalC += int(sub.CCount) * numSteps
	}

	rows := totalConstraints
	cols := numVars
	totalEntries := rows * cols

	fmt.Println("----- Aggregated Piecewise Stats -----")
	fmt.Printf("Matrix size: %d rows x %d columns\n", rows, cols)
	fmt.Printf("Constraints: %d (from %d total steps)\n", totalConstraints, totalSteps)

	fmt.Printf("A non-zero: %d, zero: %d \n", totalA, totalEntries-totalA)
	fmt.Printf("B non-zero: %d, zero: %d \n", totalB, totalEntries-totalB)
	fmt.Printf("C non-zero: %d, zero: %d \n", totalC, totalEntries-totalC)
}

// Test for DoryVeifierUniform
func TestDoryVerifierFinalStepUniform(t *testing.T) {
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()
	g1_v, g2_v := groups.RandomG1G2Affines()
	g1_e, g2_e := g1_v, g2_v
	var d fr.Element
	var chi fr.Element
	_, _ = chi.SetRandom()

	// Generate 128-bit value for d
	dBytes := make([]byte, 16)
	rand.Read(dBytes)
	var dBig big.Int
	dBig.SetBytes(dBytes)
	d.SetBigInt(&dBig)

	chiBytes := make([]byte, 16)
	rand.Read(chiBytes)
	var chiBig big.Int
	chiBig.SetBytes(chiBytes)
	chi.SetBigInt(&dBig)

	n := 10

	alpha := make([]fr.Element, n)

	s := make([]fr.Element, n)
	r := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		alphaBytes := make([]byte, 16) // 16 bytes = 128 bits
		sBytes := make([]byte, 16)
		rBytes := make([]byte, 16)

		rand.Read(alphaBytes)
		rand.Read(sBytes)
		rand.Read(rBytes)

		var alphaBig, sBig, rBig big.Int
		alphaBig.SetBytes(alphaBytes)
		sBig.SetBytes(sBytes)
		rBig.SetBytes(rBytes)

		alpha[i].SetBigInt(&alphaBig)

		s[i].SetBigInt(&sBig)
		r[i].SetBigInt(&rBig)
	}
	circuit := &DoryVerifierFinalStepUniform{
		C:                field_tower.FromE12(&a),
		D1:               field_tower.FromE12(&b),
		D2:               field_tower.FromE12(&c),
		E1:               groups.FromG1Affine(&g1_e),
		E2:               groups.FromBNG2Affine(&g2_e),
		Chi:              chi,
		Gamma1:           groups.FromG1Affine(&g1_v),
		D_times_Gamma1:   groups.FromG1Affine(&g1_v),
		Gamma2:           groups.FromBNG2Affine(&g2_v),
		DInvTimes_Gamma2: groups.FromBNG2Affine(&g2_v),
		V1:               groups.FromG1Affine(&g1_v),
		V2:               groups.FromBNG2Affine(&g2_v),
		D:                d,
		S:                utils.MakeFrontendVariable(s),
		R:                utils.MakeFrontendVariable(r),
		Alpha:            utils.MakeFrontendVariable(alpha),
		Step: &DoryVerifierFinalStep{
			S:     utils.MakeFrontendVariable(s),
			R:     utils.MakeFrontendVariable(r),
			Alpha: utils.MakeFrontendVariable(alpha),
		},
	}

	r1cs := circuit.CreateStepCircuit()
	_ = circuit.GenerateWitness(r1cs)

}
