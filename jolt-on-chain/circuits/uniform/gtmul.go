package uniform

import (
	"github.com/arithmic/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type GTMul struct {
	In1         [12]frontend.Variable `gnark:",public"`
	In2         [12]frontend.Variable `gnark:",public"`
	Quotient    [11]frontend.Variable `gnark:",public"`
	Remainder   [12]frontend.Variable `gnark:",public"`
	DivisorEval fr.Element
	rPowers     [13]fr.Element
}

func (circuit *GTMul) Define(api frontend.API) error {
	in1Eval := frontend.Variable(0)
	in2Eval := frontend.Variable(0)
	qEval := frontend.Variable(0)
	rEval := frontend.Variable(0)

	//Evaluate in1, in2,Remainder  at r
	for i := 0; i < 12; i++ {
		in1Eval = api.Add(in1Eval, api.Mul(circuit.In1[i], circuit.rPowers[i]))
		in2Eval = api.Add(in2Eval, api.Mul(circuit.In2[i], circuit.rPowers[i]))
		rEval = api.Add(rEval, api.Mul(circuit.Remainder[i], circuit.rPowers[i]))
	}

	//Evaluate Quotient at r
	for i := 0; i < 11; i++ {
		qEval = api.Add(qEval, api.Mul(circuit.Quotient[i], circuit.rPowers[i]))
	}

	rq := api.Mul(circuit.DivisorEval, qEval)
	in1in2 := api.Mul(in1Eval, in2Eval)
	api.AssertIsEqual(in1in2, api.Add(rEval, rq))
	return nil
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

	// Quotient degree = dividend degree - divisor degree
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
