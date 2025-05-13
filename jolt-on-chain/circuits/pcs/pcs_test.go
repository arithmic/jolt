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
	bn254_fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
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
	In  field_tower.Fp12  `gnark:",public"`
	Exp frontend.Variable `gnark:",public"`
	Acc field_tower.Fp12
}

func (circuit *GTUniformCircuit) Define(api frontend.API) error {
	gtAPI := field_tower.NewExt12(api)
	gtAPI.Mul(&circuit.Acc, gtAPI.Exp(&circuit.In, &circuit.Exp))
	return nil
}
func TestUniformGTExp(t *testing.T) {
	var a [100]bn254.E12
	var b [100]bn254_fp.Element
	//var bBigInt [100]big.Int
	for idx := 0; idx < 100; idx++ {
		_, _ = a[idx].SetRandom()
		_, _ = b[idx].SetRandom()
		//b[idx].BigInt(&bBigInt[idx])
	}

	//c.ScalarMultiplication(&a, b1.)

	//var exp [250]fr.Element
	//for i := 0; i < 250; i++ {
	//	b_big, _ := rand.Int(rand.Reader, fp.Modulus())
	//	exp[i].SetBigInt(b_big)
	//}

	var circuit GTUniformCircuit
	start := time.Now()
	uniformConstraints, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	duration := time.Since(start)
	fmt.Printf("Circuit compilation time 2 : %s\n", duration)
	_, aCount, bCount, cCount := ExtractConstraints(uniformConstraints)
	println("aCount:", aCount, "bCount:", bCount, "cCount:", cCount)
	
	var frZero, frOne fr.Element
	frZero.SetZero()
	frOne.SetOne()

	var one = field_tower.Fp12{A0: field_tower.Fp6{A0: field_tower.Fp2{A0: frOne, A1: frZero},
		A1: field_tower.Fp2{A0: frZero, A1: frZero},
		A2: field_tower.Fp2{A0: frZero, A1: frZero}},
		A1: field_tower.Fp6{A0: field_tower.Fp2{A0: frZero, A1: frZero},
			A1: field_tower.Fp2{A0: frZero, A1: frZero},
			A2: field_tower.Fp2{A0: frZero, A1: frZero}}}

	assignment := &GTUniformCircuit{
		In:  field_tower.FromE12(&a[0]),
		Exp: fr.Element(b[0]),
		Acc: one,
	}

	start = time.Now()
	witness, _ := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())

	wit, _ := uniformConstraints.Solve(witness)
	z := wit.(*cs.R1CSSolution).W
	println("Witness size : ", len(z))

	var extendZ fr.Vector

	for idx := 0; idx < len(z); idx++ {
		extendZ = append(extendZ, z[idx])
	}

	for idx := 0; idx < 100-1; idx++ {
		zLen := len(z)
		Acc := field_tower.Fp12{A0: field_tower.Fp6{A0: field_tower.Fp2{A0: z[zLen-12], A1: z[zLen-11]}, A1: field_tower.Fp2{A0: z[zLen-10], A1: z[zLen-9]}, A2: field_tower.Fp2{A0: z[zLen-8], A1: z[zLen-7]}}, A1: field_tower.Fp6{A0: field_tower.Fp2{A0: z[zLen-6], A1: z[zLen-5]}, A1: field_tower.Fp2{A0: z[zLen-4], A1: z[zLen-3]}, A2: field_tower.Fp2{A0: z[zLen-2], A1: z[zLen-1]}}}
		assignment := &GTUniformCircuit{
			In:  field_tower.FromE12(&a[idx+1]),
			Exp: fr.Element(b[idx+1]),
			Acc: Acc,
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

func TestUniformG1Scalar(t *testing.T) {
	var a [250]bn254.G1Affine
	for i := 0; i < 250; i++ {
		a[i] = groups.RandomG1Affine()
	}

	//c.ScalarMultiplication(&a, b1.)

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
