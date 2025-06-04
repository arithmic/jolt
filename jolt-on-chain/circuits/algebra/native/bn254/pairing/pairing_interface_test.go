package pairing

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"testing"

	"github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/uniform"

	"github.com/arithmic/gnark/constraint"
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

type PairingUniformCircuit struct {
	Q   groups.G2Affine
	P   groups.G1Projective
	Res field_tower.Fp12 `gnark:",public"`

	p   bn254.G1Affine
	q   bn254.G2Affine
	res bn254.E12
}

func (circuit *PairingUniformCircuit) Define(api frontend.API) error {

	return nil
}

func (circuit *PairingUniformCircuit) Compile() *constraint.ConstraintSystem {
	circuitR1CS, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("err in compilation is ", err)
	}
	return &circuitR1CS
}

func (circuit *PairingUniformCircuit) Hint() {
	// sets res given p and q
	circuit.res = *MillerLoop_fn(&circuit.q, &circuit.p)
}

func (circuit *PairingUniformCircuit) ExtractMatrices(circuitR1CS constraint.ConstraintSystem) ([]uniform.Constraint, int, int, int) {
	var outputConstraints []uniform.Constraint
	var aCount, bCount, cCount int

	// Assert to R1CS to get access to R1CS-specific methods
	nR1CS, ok := circuitR1CS.(constraint.R1CS)
	if !ok {
		return outputConstraints, 0, 0, 0 // or handle error
	}
	constraints := nR1CS.GetR1Cs()
	for _, r1c := range constraints {
		singular := uniform.Constraint{
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

func (circuit *PairingUniformCircuit) GenerateWitness(pairing_circuit PairingUniformCircuit, r1cs *constraint.ConstraintSystem, _ uint32) grumpkin_fr.Vector {
	// Call GenerateWitness of MillerUniformCircuit for n = 64
	var miller_circuit MillerUniformCircuit

	n := 64
	circuits := make([]*MillerUniformCircuit, n)

	bits := []int{
		0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
		0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
		-1, 0, 0, 0, 1, 0, 1,
	}

	Rin := ToProjective_fn(&pairing_circuit.q)
	var neg_Q bn254.G2Affine
	neg_Q.X = pairing_circuit.q.X
	neg_Q.Y.A1.Neg(&pairing_circuit.q.Y.A1)
	neg_Q.Y.A0.Neg(&pairing_circuit.q.Y.A0)
	var FIn bn254.E12
	FIn.SetOne()

	circuits[0].rin = Rin
	circuits[0].q = circuit.q
	circuits[0].p = circuit.p
	circuits[0].fIn = FIn
	circuits[0].negQ = neg_Q
	circuits[0].bit = bits[n-1]
	circuits[0].Hint()
	circuits[0].P = groups.AffineFromG1Affine(&pairing_circuit.p)
	circuits[0].Q = groups.G2AffineFromBNG2Affine(&pairing_circuit.q)
	circuits[0].FIn = field_tower.FromE12(&circuits[0].fIn)
	circuits[0].Rin = groups.FromBNG2Affine(&pairing_circuit.q)
	circuits[0].NegQ = groups.G2AffineFromBNG2Affine(&circuits[0].negQ)
	circuits[0].Bit = bits[n-1]
	circuits[0].FOut[0] = field_tower.FromE12(&circuits[0].fOut[0])
	circuits[0].FOut[1] = field_tower.FromE12(&circuits[0].fOut[1])
	circuits[0].FOut[2] = field_tower.FromE12(&circuits[0].fOut[2])
	circuits[0].Rout = G2ProjectiveFromBNG2Projective(&circuits[0].rout)

	for i := 1; i < n; i++ {
		circuits[i] = &MillerUniformCircuit{
			FIn:  circuits[0].FIn, // dummmy value
			P:    groups.AffineFromG1Affine(&pairing_circuit.p),
			Rin:  circuits[0].Rin, // dummmy value
			Q:    groups.G2AffineFromBNG2Affine(&pairing_circuit.q),
			NegQ: groups.G2AffineFromBNG2Affine(&neg_Q),
			Rout: circuits[0].Rout, // dummmy value
			FOut: circuits[0].FOut, // dummmy value
			Bit:  bits[n-1-i],

			fIn:  FIn, // dummmy value
			p:    pairing_circuit.p,
			rin:  Rin, // dummmy value
			q:    pairing_circuit.q,
			negQ: neg_Q,
			rout: circuits[0].rout, // dummmy value
			bit:  bits[n-1-i],
			fOut: circuits[0].fOut, // dummmy value
		}
	}

	// miller looop's lopp witness to be appended by final step witness later
	extendZ := miller_circuit.GenerateWitness(circuits, r1cs, 64)

	var miller_final_circuit *MillerEllFinalStepCircuit

	final_circuits := make([]*MillerEllFinalStepCircuit, 1)

	final_circuits[0] = &MillerEllFinalStepCircuit{
		FIn:  circuits[n-1].FOut[2],
		P:    groups.AffineFromG1Affine(&pairing_circuit.p),
		Rin:  circuits[n-1].Rout,
		Q:    groups.G2AffineFromBNG2Affine(&pairing_circuit.q),
		Rout: circuits[n-1].Rout,    // dummy value
		FOut: circuits[n-1].FOut[0], // dummy value
		fIn:  circuits[n-1].fOut[2],
		fOut: circuits[n-1].fOut[0], // dummy value
		p:    pairing_circuit.p,
		rin:  circuits[n-1].rout,
		q:    pairing_circuit.q,
		rout: circuits[n-1].rout, // dummy value
	}
	miller_final_circuit = &MillerEllFinalStepCircuit{}

	final_witness := miller_final_circuit.GenerateWitness(final_circuits, r1cs, 1)
	for i := 0; i < len(final_witness); i++ {
		extendZ = append(extendZ, final_witness[i])
	}

	return extendZ
}

func (circuit *MillerUniformCircuit) Hint() {
	circuit.rout, circuit.fOut[0], circuit.fOut[1], circuit.fOut[2] = MillerLoopStepIntegrated_fn(&circuit.rin, &circuit.q, &circuit.negQ, &circuit.p, &circuit.fIn, circuit.bit)
}

func (circuit *MillerUniformCircuit) Compile() *constraint.ConstraintSystem {
	circuitR1CS, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("err in compilation is ", err)
	}
	return &circuitR1CS
}

func (circuit *MillerUniformCircuit) GenerateWitness(circuits []*MillerUniformCircuit, r1cs *constraint.ConstraintSystem, _ uint32) grumpkin_fr.Vector {
	var witness grumpkin_fr.Vector

	var fIn bn254.E12
	fIn.SetOne()
	circuits[0].FIn = field_tower.FromE12(&fIn)

	for i := 1; i < len(circuits); i++ {
		circuits[i].FIn = circuits[i-1].FOut[2]
		circuits[i].P = circuits[0].P
		circuits[i].Rin = circuits[i-1].Rout
		circuits[i].Q = circuits[0].Q
		circuits[i].NegQ = circuits[0].NegQ

		circuits[i].fIn = circuits[i-1].fOut[2]
		circuits[i].rin = circuits[i-1].rout

		circuits[i].Hint()
		circuits[i].Rout = G2ProjectiveFromBNG2Projective(&circuits[i].rout)
		circuits[i].FOut[0] = field_tower.FromE12(&circuits[i].fOut[0])
		circuits[i].FOut[1] = field_tower.FromE12(&circuits[i].fOut[1])
		circuits[i].FOut[2] = field_tower.FromE12(&circuits[i].fOut[2])
	}

	for i := 0; i < len(circuits); i++ {
		w, err := frontend.NewWitness(circuits[i], ecc.GRUMPKIN.ScalarField())
		if err != nil {
			fmt.Println("err in generate witness is ", err)
		}
		wSolved, _ := (*r1cs).Solve(w)

		witnessStep := wSolved.(*cs.R1CSSolution).W
		for _, elem := range witnessStep {
			witness = append(witness, grumpkin_fr.Element(elem))
		}
	}
	return witness
}

func (circuit *MillerEllFinalStepCircuit) Hint() {
	circuit.rout, circuit.fOut = FinalMillerLoopStepIntegrated_fn(&circuit.rin, &circuit.q, &circuit.p, &circuit.fIn)
}

func (circuit *MillerEllFinalStepCircuit) Compile() *constraint.ConstraintSystem {
	circuitR1CS, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("err in compilation is ", err)
	}
	return &circuitR1CS
}

func (c *MillerEllFinalStepCircuit) Define(api frontend.API) error {
	pairing_api := New(api)

	// Run final step logic
	rOut, fOut := pairing_api.FinalMillerLoopStepIntegrated(&c.Rin, &c.Q, &c.P, &c.FIn)

	// Constrain Rout to match computed rOut
	pairing_api.e2.AssertIsEqual(&rOut.X, &c.Rout.X)
	pairing_api.e2.AssertIsEqual(&rOut.Y, &c.Rout.Y)
	pairing_api.e2.AssertIsEqual(&rOut.Z, &c.Rout.Z)

	pairing_api.e12.AssertIsEqual(&fOut, &c.FOut)

	return nil
}

func (circuit *MillerEllFinalStepCircuit) GenerateWitness(circuits []*MillerEllFinalStepCircuit, r1cs *constraint.ConstraintSystem, _ uint32) grumpkin_fr.Vector {
	var witness grumpkin_fr.Vector

	// For the final step, we only need circuits[0]
	c := circuits[0]

	// Call Hint to compute native values
	c.Hint()

	// Fill circuit fields based on native output
	c.Rout = G2ProjectiveFromBNG2Projective(&c.rout)
	c.FOut = field_tower.FromE12(&c.fOut)

	// Generate witness
	w, err := frontend.NewWitness(c, ecc.GRUMPKIN.ScalarField())
	if err != nil {
		fmt.Println("error generating witness:", err)
		return witness
	}

	wSolved, err := (*r1cs).Solve(w)
	if err != nil {
		fmt.Println("error solving R1CS:", err)
		return witness
	}

	witnessStep := wSolved.(*cs.R1CSSolution).W
	for _, elem := range witnessStep {
		witness = append(witness, grumpkin_fr.Element(elem))
	}

	return witness
}

// Test the miller output from witness with the MillerLoop function
func TestCircuitMillerFinalUniformWithInterface(t *testing.T) {
	// Define the circuit
	n := 64

	var dummyCircuit *MillerUniformCircuit

	circuits := make([]*MillerUniformCircuit, n)

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

	Rin := ToProjective_fn(&Q)
	var neg_Q bn254.G2Affine
	neg_Q.X = Q.X
	neg_Q.Y.A1.Neg(&Q.Y.A1)
	neg_Q.Y.A0.Neg(&Q.Y.A0)

	var FIn bn254.E12
	FIn.SetOne()

	Rout, f1, f2, f3 := MillerLoopStepIntegrated_fn(&Rin, &Q, &neg_Q, &P, &FIn, bits[n-1])

	var FOut [3]field_tower.Fp12

	FOut[0] = field_tower.FromE12(&f1)
	FOut[1] = field_tower.FromE12(&f2)
	FOut[2] = field_tower.FromE12(&f3)

	for i := 0; i < n; i++ {
		circuits[i] = &MillerUniformCircuit{
			FIn:  field_tower.FromE12(&FIn),
			P:    groups.AffineFromG1Affine(&P),
			Rin:  groups.FromBNG2Affine(&Q),
			Q:    groups.G2AffineFromBNG2Affine(&Q),
			NegQ: groups.G2AffineFromBNG2Affine(&neg_Q),
			Rout: G2ProjectiveFromBNG2Projective(&Rout),
			FOut: FOut,
			Bit:  bits[n-1-i],

			fIn:  FIn,
			p:    P,
			rin:  Rin,
			q:    Q,
			negQ: neg_Q,
			rout: G2Projective{X: Rout.X, Y: Rout.Y, Z: Rout.Z},
			bit:  bits[n-1-i],
			fOut: [3]bn254.E12{f1, f2, f3},
		}
	}

	dummyCircuit = &MillerUniformCircuit{}
	r1cs := dummyCircuit.Compile()
	_, _, _, _ = dummyCircuit.ExtractMatrices(*r1cs)
	extendZ := dummyCircuit.GenerateWitness(circuits, r1cs, 64)

	// extract values from circuit n - 1 and put them as inputs for MillerEllFinalStepCircuit circuit
	var miller_final_circuit *MillerEllFinalStepCircuit

	final_circuits := make([]*MillerEllFinalStepCircuit, 1)

	final_circuits[0] = &MillerEllFinalStepCircuit{
		FIn:  circuits[n-1].FOut[2],
		P:    groups.AffineFromG1Affine(&P),
		Rin:  circuits[n-1].Rout,
		Q:    groups.G2AffineFromBNG2Affine(&Q),
		Rout: circuits[n-1].Rout,    // dummy value
		FOut: circuits[n-1].FOut[0], // dummy value
		fIn:  circuits[n-1].fOut[2],
		fOut: circuits[n-1].fOut[0], // dummy value
		p:    P,
		rin:  circuits[n-1].rout,
		q:    Q,
		rout: circuits[n-1].rout, // dummy value
	}
	miller_final_circuit = &MillerEllFinalStepCircuit{}

	r1cs_1 := miller_final_circuit.Compile()
	final_witness := miller_final_circuit.GenerateWitness(final_circuits, r1cs_1, 1)

	for i := 0; i < len(final_witness); i++ {
		extendZ = append(extendZ, final_witness[i])
	}

	// result from miller_fn
	actual_miller_result1 := MillerLoop_fn(&Q, &P)
	P_arr := []bn254.G1Affine{P}
	Q_arr := []bn254.G2Affine{Q}
	actual_miller_res, _ := bn254.MillerLoop(P_arr, Q_arr)
	actual_res_after_final_exp := bn254.FinalExponentiation(&actual_miller_res)

	miller_final_res_from_witness := bn254.E12{}
	miller_final_res_from_witness.C0.B0.A0.SetString(extendZ[22976 + 19].String())
	miller_final_res_from_witness.C0.B0.A1.SetString(extendZ[22976 + 20].String())
	miller_final_res_from_witness.C0.B1.A0.SetString(extendZ[22976 + 21].String())
	miller_final_res_from_witness.C0.B1.A1.SetString(extendZ[22976 + 22].String())
	miller_final_res_from_witness.C0.B2.A0.SetString(extendZ[22976 + 23].String())
	miller_final_res_from_witness.C0.B2.A1.SetString(extendZ[22976 + 24].String())
	miller_final_res_from_witness.C1.B0.A0.SetString(extendZ[22976 + 25].String())
	miller_final_res_from_witness.C1.B0.A1.SetString(extendZ[22976 + 26].String())
	miller_final_res_from_witness.C1.B1.A0.SetString(extendZ[22976 + 27].String())
	miller_final_res_from_witness.C1.B1.A1.SetString(extendZ[22976 + 28].String())
	miller_final_res_from_witness.C1.B2.A0.SetString(extendZ[22976 + 29].String())
	miller_final_res_from_witness.C1.B2.A1.SetString(extendZ[22976 + 30].String())
	// miller_final_res_from_witness.C0.B0.A0.SetString(extendZ[22976 + 22991].String())
	// miller_final_res_from_witness.C0.B0.A1.SetString(extendZ[22992].String())
	// miller_final_res_from_witness.C0.B1.A0.SetString(extendZ[22993].String())
	// miller_final_res_from_witness.C0.B1.A1.SetString(extendZ[22994].String())
	// miller_final_res_from_witness.C0.B2.A0.SetString(extendZ[22995].String())
	// miller_final_res_from_witness.C0.B2.A1.SetString(extendZ[22996].String())
	// miller_final_res_from_witness.C1.B0.A0.SetString(extendZ[22997].String())
	// miller_final_res_from_witness.C1.B0.A1.SetString(extendZ[22998].String())
	// miller_final_res_from_witness.C1.B1.A0.SetString(extendZ[22999].String())
	// miller_final_res_from_witness.C1.B1.A1.SetString(extendZ[23000].String())
	// miller_final_res_from_witness.C1.B2.A0.SetString(extendZ[23001].String())
	// miller_final_res_from_witness.C1.B2.A1.SetString(extendZ[23002].String())

	res_after_final_exp_for_witness := bn254.FinalExponentiation(&miller_final_res_from_witness)

	val := actual_res_after_final_exp.Equal(&res_after_final_exp_for_witness)
	if val == false {
		fmt.Println("The result is not equal after exponentiation with gnark functions")
	} else {
		fmt.Println("The result is equal after exponentiation with gnark functions")
	}

	val1 := actual_miller_result1.Equal(&miller_final_res_from_witness)
	if val1 == false {
		fmt.Println("The result is not equal with new miller function")
	} else {
		fmt.Println("The result is equal with new miller function")
	}
}

// // TODO fix the test to use the interface for complete Miller loop
// func TestCircuitPairingUniformWithInterface(t *testing.T) {
// 	// Define the circuit

// 	var dummyCircuit *PairingUniformCircuit

// 	_, _, g1GenAff, g2GenAff := bn254.Generators()

// 	var P bn254.G1Affine
// 	var Q bn254.G2Affine

// 	scalar, _ := rand.Int(rand.Reader, bn254_fr.Modulus())
// 	P.ScalarMultiplication(&g1GenAff, scalar)
// 	Q.ScalarMultiplication(&g2GenAff, scalar)
// 	circuit := PairingUniformCircuit{
// 		Q:   groups.G2AffineFromBNG2Affine(&Q),
// 		P:   groups.FromG1Affine(&P),
// 		Res: field_tower.FromE12(&bn254.E12{}), // Initialize with empty E12

// 		p: P,
// 		q: Q,
// 	}

// 	dummyCircuit = &PairingUniformCircuit{}
// 	r1cs := dummyCircuit.Compile()
// 	_, _, _, _ = dummyCircuit.ExtractMatrices(*r1cs)
// 	_ = dummyCircuit.GenerateWitness(circuit, r1cs, 64)
// }
