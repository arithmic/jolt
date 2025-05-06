package pcs

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	constraint "github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/groups"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
	"strconv"
	"testing"
	"time"
)

type UniformCircuit struct {
	In  groups.G1Projective `gnark:",public"`
	Exp frontend.Variable   `gnark:",public"`
	Acc groups.G1Projective
}

func (circuit *UniformCircuit) Define(api frontend.API) error {
	groupAPI := &groups.G1API{Api: api}
	groupAPI.Add(&circuit.Acc, groupAPI.ScalarMul(&circuit.In, &circuit.Exp))
	return nil
}

func TestUniformCircuit(t *testing.T) {
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

	var circuit UniformCircuit
	start := time.Now()
	uniformConstraints, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
	duration := time.Since(start)

	var zero, one fr.Element
	zero.SetZero()
	one.SetOne()

	assignment := &UniformCircuit{
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
		assignment := &UniformCircuit{
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

func ExtractConstraints(r1cs constraint.ConstraintSystem) []Constraint {
	var outputConstraints []Constraint

	// Assert to R1CS to get access to R1CS-specific methods
	nR1CS, ok := r1cs.(constraint.R1CS)
	if !ok {
		return outputConstraints // or handle error
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
		}
		for _, term := range r1c.R {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.B[col] = val
		}
		for _, term := range r1c.O {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.C[col] = val
		}

		outputConstraints = append(outputConstraints, singular)
	}

	return outputConstraints
}
