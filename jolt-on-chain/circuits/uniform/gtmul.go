package uniform

import (
	"fmt"

	"github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type GTMul struct {
	Acc           [12]frontend.Variable
	In            [12]frontend.Variable
	Quot          [11]frontend.Variable
	Rem           [12]frontend.Variable
	DivisorEval   fr.Element
	reduciblePoly []fr.Element
	rPowers       [13]fr.Element
}

func (circuit *GTMul) Define(api frontend.API) error {
	accEval := frontend.Variable(0)
	inEval := frontend.Variable(0)
	qEval := frontend.Variable(0)
	rEval := frontend.Variable(0)

	//Evaluate acc, in2, Rem at r
	for i := 0; i < 12; i++ {
		accEval = api.Add(accEval, api.Mul(circuit.Acc[i], circuit.rPowers[i]))
		inEval = api.Add(inEval, api.Mul(circuit.In[i], circuit.rPowers[i]))
		rEval = api.Add(rEval, api.Mul(circuit.Rem[i], circuit.rPowers[i]))
	}

	//Evaluate Quot at r
	for i := 0; i < 11; i++ {
		qEval = api.Add(qEval, api.Mul(circuit.Quot[i], circuit.rPowers[i]))
	}

	rq := api.Mul(circuit.DivisorEval, qEval)
	in1in2 := api.Mul(accEval, inEval)
	api.AssertIsEqual(in1in2, api.Add(rEval, rq))
	return nil
}

func (circuit *GTMul) GenerateWitness(constraints constraint.ConstraintSystem) fr.Vector {
	w, err := frontend.NewWitness(circuit, ecc.GRUMPKIN.ScalarField())

	if err != nil {
		fmt.Println("Failed to create witness object", err)
	}
	wit, err := constraints.Solve(w)
	if err != nil {
		fmt.Println("Witness generation failed ", err)
	}
	wSolved := wit.(*cs.R1CSSolution).W

	return wSolved
}

func (circuit *GTMul) Hint() {
	in1, _ := convertFrontendArrayToFrArray(circuit.Acc[:])
	in2, _ := convertFrontendArrayToFrArray(circuit.In[:])
	in1Tower := ToTower(in1)
	in2Tower := ToTower(in2)
	var in1in2Tower bn254.E12
	in1in2Tower.Mul(&in1Tower, &in2Tower)

	in1in2 := FromE12(&in1in2Tower)

	in1in2Poly := multiplyPolynomials(in1, in2)
	quotient := computeQuotientPoly(in1in2Poly, circuit.reduciblePoly, in1in2)

	circuit.Quot = [11]frontend.Variable(makeFrontendVariable(quotient))
	circuit.Rem = [12]frontend.Variable(makeFrontendVariable(in1in2))
}

type GTMultiMul struct {
	in        [][]fr.Element
	out       []fr.Element
	rPowers   [13]fr.Element
	gtMulStep *GTMul
}

func (gtMultiMul *GTMultiMul) CreateStepCircuit() constraint.ConstraintSystem {

	reduciblePoly := make([]fr.Element, 13)
	reduciblePoly[0].SetInt64(82)
	reduciblePoly[6].SetInt64(-18)
	reduciblePoly[12].SetOne()
	divisorEval := fr.Element{}

	for i := 0; i < len(reduciblePoly); i++ {
		var temp fr.Element
		temp.Mul(&reduciblePoly[i], &gtMultiMul.rPowers[i])
		divisorEval.Add(&divisorEval, &temp)
	}

	gtMultiMul.gtMulStep = &GTMul{
		DivisorEval:   divisorEval,
		reduciblePoly: reduciblePoly,
		rPowers:       gtMultiMul.rPowers,
	}

	gtMulConstraints, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, gtMultiMul.gtMulStep)

	return gtMulConstraints

}

func (gtMultiMul *GTMultiMul) GenerateWitness(constraints constraint.ConstraintSystem) fr.Vector {

	gtMultiMul.gtMulStep.Acc = [12]frontend.Variable(makeFrontendVariable(gtMultiMul.in[0]))

	var witness fr.Vector

	for i := 1; i < len(gtMultiMul.in); i++ {
		gtMultiMul.gtMulStep.In = [12]frontend.Variable(makeFrontendVariable(gtMultiMul.in[i]))

		gtMultiMul.gtMulStep.Hint()

		witnessStep := gtMultiMul.gtMulStep.GenerateWitness(constraints)

		witness = append(witness, witnessStep...)

		gtMultiMul.gtMulStep.Acc = gtMultiMul.gtMulStep.Rem
	}

	return witness

}

func multiplyPolynomials(a, b []fr.Element) []fr.Element {
	degree := len(a) + len(b) - 1
	result := make([]fr.Element, degree)

	for i := 0; i < len(a); i++ {
		for j := 0; j < len(b); j++ {
			var intRes fr.Element
			intRes.Mul(&a[i], &b[j])
			result[i+j].Add(&result[i+j], &intRes)
		}
	}
	return result
}

// TODO:- Verify
func computeQuotientPoly(divPoly, redPoly, remPoly []fr.Element) []fr.Element {
	// First, compute divPoly - remPoly
	fMinusR := make([]fr.Element, len(divPoly))
	copy(fMinusR, divPoly)

	// Subtract remPoly from fMinusR (element-wise for corresponding indices)
	for i := 0; i < len(remPoly) && i < len(fMinusR); i++ {
		fMinusR[i].Sub(&fMinusR[i], &remPoly[i])
	}

	// Find the actual degree of the dividend (fMinusR) by removing leading zeros
	dividendDegree := len(fMinusR) - 1
	for dividendDegree >= 0 && fMinusR[dividendDegree].IsZero() {
		dividendDegree--
	}

	// Find the actual degree of the divisor (redPoly) by removing leading zeros
	divisorDegree := len(redPoly) - 1
	for divisorDegree >= 0 && redPoly[divisorDegree].IsZero() {
		divisorDegree--
	}

	// Always return a quotient of length 11 (expected quotient degree for this application)
	q := make([]fr.Element, 11)

	// If dividend degree < divisor degree, quotient is zero (already initialized as zeros)
	if dividendDegree < divisorDegree || dividendDegree < 0 {
		return q
	}

	// Quot degree = dividend degree - divisor degree
	quotientDegree := dividendDegree - divisorDegree

	// Ensure we don't exceed the expected quotient length
	if quotientDegree >= 11 {
		quotientDegree = 10 // Maximum index for length 11 array
	}

	// Get inverse of leading coefficient of divisor
	var invLeading fr.Element
	invLeading.Inverse(&redPoly[divisorDegree])

	// Polynomial long division
	for i := dividendDegree; i >= divisorDegree; i-- {
		if fMinusR[i].IsZero() {
			continue
		}

		quotientIndex := i - divisorDegree
		if quotientIndex >= 11 {
			continue // Skip if quotient index exceeds expected length
		}

		// Calculate quotient coefficient
		var coeff fr.Element
		coeff.Mul(&fMinusR[i], &invLeading)
		q[quotientIndex].Set(&coeff)

		// Subtract coeff * redPoly * x^(i-divisorDegree) from fMinusR
		for j := 0; j <= divisorDegree; j++ {
			var temp fr.Element
			temp.Mul(&coeff, &redPoly[j])
			fMinusR[i-divisorDegree+j].Sub(&fMinusR[i-divisorDegree+j], &temp)
		}
	}

	return q
}

// FromE12 tower to direct extension conversion
func FromE12(a *bn254.E12) []fr.Element {
	// gnark-crypto uses a quadratic over cubic over quadratic 12th extension of Fp.
	// The two towers are isomorphic and the coefficients are permuted as follows:
	// 		a000 a001 a010 a011 a020 a021 a100 a101 a110 a111 a120 a121
	//      a0   a1   a2   a3   a4   a5   a6   a7   a8   a9   a10  a11
	//
	//     A0  =  a000 - 9 * a001
	//     A1  =  a100 - 9 * a101
	//     A2  =  a010 - 9 * a011
	//     A3  =  a110 - 9 * a111
	//     A4  =  a020 - 9 * a021
	//     A5  =  a120 - 9 * a121
	//     A6  =  a001
	//     A7  =  a101
	//     A8  =  a011
	//     A9  =  a111
	//     A10 =  a021
	//     A11 =  a121

	var c0, c1, c2, c3, c4, c5, t fp.Element
	t.SetUint64(9).Mul(&t, &a.C0.B0.A1)
	c0.Sub(&a.C0.B0.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B0.A1)
	c1.Sub(&a.C1.B0.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C0.B1.A1)
	c2.Sub(&a.C0.B1.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B1.A1)
	c3.Sub(&a.C1.B1.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C0.B2.A1)
	c4.Sub(&a.C0.B2.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B2.A1)
	c5.Sub(&a.C1.B2.A0, &t)

	res := []fr.Element{
		fr.Element(c0),
		fr.Element(c1),
		fr.Element(c2),
		fr.Element(c3),
		fr.Element(c4),
		fr.Element(c5),
		fr.Element(a.C0.B0.A1),
		fr.Element(a.C1.B0.A1),
		fr.Element(a.C0.B1.A1),
		fr.Element(a.C1.B1.A1),
		fr.Element(a.C0.B2.A1),
		fr.Element(a.C1.B2.A1),
	}
	return res
}

// ToTower TODO:- Test it
func ToTower(a []fr.Element) bn254.E12 {
	// gnark-crypto uses a quadratic over cubic over quadratic 12th extension of Fp.
	// The two towers are isomorphic and the coefficients are permuted as follows:
	//
	//	   tower  =  a000 a001 a010 a011 a020 a021 a100 a101 a110 a111 a120 a121
	// 	   direct = a0   a1   a2   a3   a4   a5   a6   a7   a8   a9   a10  a11
	//
	//     a000 = A0  +  9 * A6
	//     a001 = A6
	//     a010 = A2  +  9 * A8
	//     a011 = A8
	//     a020 = A4  +  9 * A10
	//     a021 = A10
	//     a100 = A1  +  9 * A7
	//     a101 = A7
	//     a110 = A3  +  9 * A9
	//     a111 = A9
	//     a120 = A5  +  9 * A11
	//     a121 = A11

	if len(a) < 12 {
		panic("slice must have at least 12 elements")
	}

	var nine fp.Element
	nine.SetUint64(9)
	a6MulNine := fp.Element(a[6])
	a6MulNine.Mul(&a6MulNine, &nine)
	a000 := fp.Element(a[0])
	a000.Add(&a000, &a6MulNine)

	a001 := fp.Element(a[6])

	a8MulNine := fp.Element(a[8])
	a8MulNine.Mul(&a8MulNine, &nine)
	a010 := fp.Element(a[2])

	a010.Add(&a010, &a8MulNine)

	a011 := fp.Element(a[8])
	a10MulNine := fp.Element(a[10])
	a10MulNine.Mul(&a10MulNine, &nine)
	a020 := fp.Element(a[4])
	a020.Add(&a020, &a10MulNine)

	a021 := fp.Element(a[10])
	a7MulNine := fp.Element(a[7])
	a7MulNine.Mul(&a7MulNine, &nine)
	a100 := fp.Element(a[1])
	a100.Add(&a100, &a7MulNine)

	a101 := fp.Element(a[7])
	a9MulNine := fp.Element(a[9])
	a9MulNine.Mul(&a9MulNine, &nine)
	a110 := fp.Element(a[3])
	a110.Add(&a110, &a9MulNine)

	a111 := fp.Element(a[9])
	a11MulNine := fp.Element(a[11])
	a11MulNine.Mul(&a11MulNine, &nine)
	a120 := fp.Element(a[5])
	a120.Add(&a120, &a11MulNine)

	a121 := fp.Element(a[11])

	tower := bn254.E12{C0: bn254.E6{B0: bn254.E2{A0: a000, A1: a001}, B1: bn254.E2{A0: a010, A1: a011}, B2: bn254.E2{A0: a020, A1: a021}},
		C1: bn254.E6{B0: bn254.E2{A0: a100, A1: a101}, B1: bn254.E2{A0: a110, A1: a111}, B2: bn254.E2{A0: a120, A1: a121}}}
	return tower
}
