package uniform

import (
	"github.com/arithmic/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type GTMul struct {
	In1         E12                   `gnark:",public"`
	In2         E12                   `gnark:",public"`
	Quotient    [11]frontend.Variable `gnark:",public"`
	Remainder   E12                   `gnark:",public"`
	DivisorEval frontend.Variable     `gnark:",public"`
	RPowers     [12]fr.Element
}

func (circuit *GTMul) Define(api frontend.API) error {
	in1Eval := make([]frontend.Variable, 13)
	in1Eval[0] = frontend.Variable(0)
	in2Eval := make([]frontend.Variable, 13)
	in2Eval[0] = frontend.Variable(0)
	qEval := make([]frontend.Variable, 12)
	qEval[0] = frontend.Variable(0)
	rEval := make([]frontend.Variable, 13)
	rEval[0] = frontend.Variable(0)
	//in1Eval := api.Add(0, 0)
	//in2Eval := api.Add(0, 0)
	//qEval := api.Add(0, 0)
	//rEval := api.Add(0, 0)
	//in1Eval, _ := api.ConstantValue(0)
	//in2Eval, _ := api.ConstantValue(0)
	//qEval, _ := api.ConstantValue(0)
	//rEval, _ := api.ConstantValue(0)
	//var in1Eval, in2Eval, qEval, rEval frontend.Variable
	//in1Eval = frontend.Variable(1)
	//in2Eval = frontend.Variable(1)
	//qEval := frontend.Variable(1)
	//rEval := frontend.Variable(1)
	////
	//in1Eval, isConstant := api.ConstantValue(0)
	//if !isConstant {
	//	panic("Failed to set constant value")
	//}
	//in2Eval, isConstant = api.ConstantValue(0)
	//if !isConstant {
	//	panic("Failed to set constant value")
	//}
	//
	//qEval, isConstant = api.ConstantValue(0)
	//if !isConstant {
	//	panic("Failed to set constant value")
	//}
	//
	//rEval, isConstant = api.ConstantValue(0)
	//if !isConstant {
	//	panic("Failed to set constant value")
	//}

	//TODO:- Write Eval Circuit.
	println("in1Eval[i+1] is", in1Eval[0])
	//Evaluate in1, in2,Remainder  at r
	for i := 0; i < 12; i++ {
		constTerm, isConstant := api.ConstantValue(circuit.RPowers[i])
		if !isConstant {
			panic("Failed to set constant value")
		}
		in1Eval[i+1] = api.Add(in1Eval[i], api.Mul(circuit.In1.Elements[i], circuit.RPowers[i]))
		//in1Eval[i+1] = api.Mul(circuit.In1.Elements[i], constTerm)
		api.Println("in1Eval[i+1] is", in1Eval[i+1])
		in2Eval[i+1] = api.Add(in2Eval[i], api.Mul(circuit.In2.Elements[i], constTerm))
		//in2Eval = api.Add(in2Eval, api.Mul(circuit.In2.Elements[i], constTerm))
		rEval[i+1] = api.Add(rEval[i], api.Mul(circuit.Remainder.Elements[i], constTerm))
	}

	//Evaluate Quotient at r
	for i := 0; i < 11; i++ {
		//constTerm, isConstant := api.ConstantValue(circuit.RPowers[i])
		//if !isConstant {
		//	panic("Failed to set constant value")
		//}
		qEval[i+1] = api.Add(qEval[i], api.Mul(circuit.Quotient[i], circuit.RPowers[i]))

	}
	rq := api.Mul(circuit.DivisorEval, qEval[11])
	in1in2 := api.Mul(in1Eval[12], in2Eval[12])
	api.AssertIsEqual(in1in2, api.Add(rEval[12], rq))
	return nil
}

type E12 struct {
	Elements [12]frontend.Variable
}

//
//func multiplyPolynomials(a, b *E12) []fr.Element {
//	degree := 23
//	result := make([]fr.Element, degree)
//
//	for i := 0; i < 12; i++ {
//		for j := 0; j < 12; j++ {
//			var intRes fr.Element
//			intRes.Mul(&a.Elements[i], &b.Elements[j])
//			result[i+j].Add(&result[i+j], &intRes)
//		}
//	}
//	return result
//}
//
//// TODO: Verify Algorithm(Source Code GPT)
//func computeQuotientPoly(f, d, r []fr.Element) []fr.Element {
//	fMinusR := make([]fr.Element, len(f))
//	copy(fMinusR, f)
//
//	// Subtract r from the tail of fMinusR
//	for i := 0; i < len(r); i++ {
//		fMinusR[i].Sub(&fMinusR[i], &r[i])
//	}
//
//	// Degree of q is len(fMinusR) - len(d) + 1
//	qDegree := len(fMinusR) - len(d) + 1
//	q := make([]fr.Element, qDegree)
//
//	var invLeading fr.Element
//	invLeading.Inverse(&d[len(d)-1]) // inverse of leading coefficient of d
//
//	// Long division
//	for i := len(fMinusR) - 1; i >= len(d)-1; i-- {
//		var coeff fr.Element
//		coeff.Mul(&fMinusR[i], &invLeading)
//		q[i-(len(d)-1)].Set(&coeff)
//
//		// Subtract coeff * d shifted
//		for j := 0; j < len(d); j++ {
//			var temp fr.Element
//			temp.Mul(&coeff, &d[j])
//			fMinusR[i-(len(d)-1)+j].Sub(&fMinusR[i-(len(d)-1)+j], &temp)
//		}
//	}
//	return q
//}

//
//func () mulDirect(a, b *E12) *E12 {
//
//	// a = a11 w^11 + a10 w^10 + a9 w^9 + a8 w^8 + a7 w^7 + a6 w^6 + a5 w^5 + a4 w^4 + a3 w^3 + a2 w^2 + a1 w + a0
//	// b = b11 w^11 + b10 w^10 + b9 w^9 + b8 w^8 + b7 w^7 + b6 w^6 + b5 w^5 + b4 w^4 + b3 w^3 + b2 w^2 + b1 w + b0
//	//
//	// Given that w^12 = 18 w^6 - 82, we can compute the product a * b as follows:
//	//
//	// a * b = d11 w^11 + d10 w^10 + d9 w^9 + d8 w^8 + d7 w^7 + d6 w^6 + d5 w^5 + d4 w^4 + d3 w^3 + d2 w^2 + d1 w + d0
//	//
//	// where:
//	//
//	// d0  =  c0  - 82 * c12 - 1476 * c18
//	// d1  =  c1  - 82 * c13 - 1476 * c19
//	// d2  =  c2  - 82 * c14 - 1476 * c20
//	// d3  =  c3  - 82 * c15 - 1476 * c21
//	// d4  =  c4  - 82 * c16 - 1476 * c22
//	// d5  =  c5  - 82 * c17
//	// d6  =  c6  + 18 * c12 + 242 * c18
//	// d7  =  c7  + 18 * c13 + 242 * c19
//	// d8  =  c8  + 18 * c14 + 242 * c20
//	// d9  =  c9  + 18 * c15 + 242 * c21
//	// d10 =  c10 + 18 * c16 + 242 * c22
//	// d11 =  c11 + 18 * c17
//	//
//	// and:
//	//
//	// c0 = a0 b0
//	// c1 = a0 b1 + a1 b0
//	// c2 = a0 b2 + a1 b1 + a2 b0
//	// c3 = a0 b3 + a1 b2 + a2 b1 + a3 b0
//	// c4 = a0 b4 + a1 b3 + a2 b2 + a3 b1 + a4 b0
//	// c5 = a0 b5 + a1 b4 + a2 b3 + a3 b2 + a4 b1 + a5 b0
//	// c6 = a0 b6 + a1 b5 + a2 b4 + a3 b3 + a4 b2 + a5 b1 + a6 b0
//	// c7 = a0 b7 + a1 b6 + a2 b5 + a3 b4 + a4 b3 + a5 b2 + a6 b1 + a7 b0
//	// c8 = a0 b8 + a1 b7 + a2 b6 + a3 b5 + a4 b4 + a5 b3 + a6 b2 + a7 b1 + a8 b0
//	// c9 = a0 b9 + a1 b8 + a2 b7 + a3 b6 + a4 b5 + a5 b4 + a6 b3 + a7 b2 + a8 b1 + a9 b0
//	// c10 = a0 b10 + a1 b9 + a2 b8 + a3 b7 + a4 b6 + a5 b5 + a6 b4 + a7 b3 + a8 b2 + a9 b1 + a10 b0
//	// c11 = a0 b11 + a1 b10 + a2 b9 + a3 b8 + a4 b7 + a5 b6 + a6 b5 + a7 b4 + a8 b3 + a9 b2 + a10 b1 + a11 b0
//	// c12 = a1 b11 + a2 b10 + a3 b9 + a4 b8 + a5 b7 + a6 b6 + a7 b5 + a8 b4 + a9 b3 + a10 b2 + a11 b1
//	// c13 = a2 b11 + a3 b10 + a4 b9 + a5 b8 + a6 b7 + a7 b6 + a8 b5 + a9 b4 + a10 b3 + a11 b2
//	// c14 = a3 b11 + a4 b10 + a5 b9 + a6 b8 + a7 b7 + a8 b6 + a9 b5 + a10 b4 + a11 b3
//	// c15 = a4 b11 + a5 b10 + a6 b9 + a7 b8 + a8 b7 + a9 b6 + a10 b5 + a11 b4
//	// c16 = a5 b11 + a6 b10 + a7 b9 + a8 b8 + a9 b7 + a10 b6 + a11 b5
//	// c17 = a6 b11 + a7 b10 + a8 b9 + a9 b8 + a10 b7 + a11 b6
//	// c18 = a7 b11 + a8 b10 + a9 b9 + a10 b8 + a11 b7
//	// c19 = a8 b11 + a9 b10 + a10 b9 + a11 b8
//	// c20 = a9 b11 + a10 b10 + a11 b9
//	// c21 = a10 b11 + a11 b10
//	// c22 = a11 b11
//
//	// d0  =  c0  - 82 * c12 - 1476 * c18
//	//     =  a0 b0  - 82 * (a1 b11 + a2 b10 + a3 b9 + a4 b8 + a5 b7 + a6 b6 + a7 b5 + a8 b4 + a9 b3 + a10 b2 + a11 b1) - 1476 * (a7 b11 + a8 b10 + a9 b9 + a10 b8 + a11 b7)
//	mone := fr.NewElement(-1)
//	d0 := fr.Eval([][]*baseEl{{&a.A0, &b.A0}, {mone, &a.A1, &b.A11}, {mone, &a.A2, &b.A10}, {mone, &a.A3, &b.A9}, {mone, &a.A4, &b.A8}, {mone, &a.A5, &b.A7}, {mone, &a.A6, &b.A6}, {mone, &a.A7, &b.A5}, {mone, &a.A8, &b.A4}, {mone, &a.A9, &b.A3}, {mone, &a.A10, &b.A2}, {mone, &a.A11, &b.A1}, {mone, &a.A7, &b.A11}, {mone, &a.A8, &b.A10}, {mone, &a.A9, &b.A9}, {mone, &a.A10, &b.A8}, {mone, &a.A11, &b.A7}}, []int{1, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 1476, 1476, 1476, 1476, 1476})
//
//	// d1  =  c1  - 82 * c13 - 1476 * c19
//	//     =  a0 b1 + a1 b0  - 82 * (a2 b11 + a3 b10 + a4 b9 + a5 b8 + a6 b7 + a7 b6 + a8 b5 + a9 b4 + a10 b3 + a11 b2) - 1476 * (a8 b11 + a9 b10 + a10 b9 + a11 b8)
//	d1 := fr.Eval([][]*baseEl{{&a.A0, &b.A1}, {&a.A1, &b.A0}, {mone, &a.A2, &b.A11}, {mone, &a.A3, &b.A10}, {mone, &a.A4, &b.A9}, {mone, &a.A5, &b.A8}, {mone, &a.A6, &b.A7}, {mone, &a.A7, &b.A6}, {mone, &a.A8, &b.A5}, {mone, &a.A9, &b.A4}, {mone, &a.A10, &b.A3}, {mone, &a.A11, &b.A2}, {mone, &a.A8, &b.A11}, {mone, &a.A9, &b.A10}, {mone, &a.A10, &b.A9}, {mone, &a.A11, &b.A8}}, []int{1, 1, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 1476, 1476, 1476, 1476})
//
//	// d2  =  c2  - 82 * c14 - 1476 * c20
//	//     =  a0 b2 + a1 b1 + a2 b0  - 82 * (a3 b11 + a4 b10 + a5 b9 + a6 b8 + a7 b7 + a8 b6 + a9 b5 + a10 b4 + a11 b3) - 1476 * (a9 b11 + a10 b10 + a11 b9)
//	d2 := fr.Eval([][]*baseEl{{&a.A0, &b.A2}, {&a.A1, &b.A1}, {&a.A2, &b.A0}, {mone, &a.A3, &b.A11}, {mone, &a.A4, &b.A10}, {mone, &a.A5, &b.A9}, {mone, &a.A6, &b.A8}, {mone, &a.A7, &b.A7}, {mone, &a.A8, &b.A6}, {mone, &a.A9, &b.A5}, {mone, &a.A10, &b.A4}, {mone, &a.A11, &b.A3}, {mone, &a.A9, &b.A11}, {mone, &a.A10, &b.A10}, {mone, &a.A11, &b.A9}}, []int{1, 1, 1, 82, 82, 82, 82, 82, 82, 82, 82, 82, 1476, 1476, 1476})
//
//	// d3  =  c3  - 82 * c15 - 1476 * c21
//	//     =  a0 b3 + a1 b2 + a2 b1 + a3 b0  - 82 * (a4 b11 + a5 b10 + a6 b9 + a7 b8 + a8 b7 + a9 b6 + a10 b5 + a11 b4) - 1476 * (a10 b11 + a11 b10)
//	d3 := fr.Eval([][]*baseEl{{&a.A0, &b.A3}, {&a.A1, &b.A2}, {&a.A2, &b.A1}, {&a.A3, &b.A0}, {mone, &a.A4, &b.A11}, {mone, &a.A5, &b.A10}, {mone, &a.A6, &b.A9}, {mone, &a.A7, &b.A8}, {mone, &a.A8, &b.A7}, {mone, &a.A9, &b.A6}, {mone, &a.A10, &b.A5}, {mone, &a.A11, &b.A4}, {mone, &a.A10, &b.A11}, {mone, &a.A11, &b.A10}}, []int{1, 1, 1, 1, 82, 82, 82, 82, 82, 82, 82, 82, 1476, 1476})
//
//	// d4  =  c4  - 82 * c16 - 1476 * c22
//	//     =  a0 b4 + a1 b3 + a2 b2 + a3 b1 + a4 b0  - 82 * (a5 b11 + a6 b10 + a7 b9 + a8 b8 + a9 b7 + a10 b6 + a11 b5) - 1476 * a11 b11
//	d4 := fr.Eval([][]*baseEl{{&a.A0, &b.A4}, {&a.A1, &b.A3}, {&a.A2, &b.A2}, {&a.A3, &b.A1}, {&a.A4, &b.A0}, {mone, &a.A5, &b.A11}, {mone, &a.A6, &b.A10}, {mone, &a.A7, &b.A9}, {mone, &a.A8, &b.A8}, {mone, &a.A9, &b.A7}, {mone, &a.A10, &b.A6}, {mone, &a.A11, &b.A5}, {mone, &a.A11, &b.A11}}, []int{1, 1, 1, 1, 1, 82, 82, 82, 82, 82, 82, 82, 1476})
//
//	// d5  =  c5  - 82 * c17
//	//     =  a0 b5 + a1 b4 + a2 b3 + a3 b2 + a4 b1 + a5 b0  - 82 * (a6 b11 + a7 b10 + a8 b9 + a9 b8 + a10 b7 + a11 b6)
//	d5 := fr.Eval([][]*baseEl{{&a.A0, &b.A5}, {&a.A1, &b.A4}, {&a.A2, &b.A3}, {&a.A3, &b.A2}, {&a.A4, &b.A1}, {&a.A5, &b.A0}, {mone, &a.A6, &b.A11}, {mone, &a.A7, &b.A10}, {mone, &a.A8, &b.A9}, {mone, &a.A9, &b.A8}, {mone, &a.A10, &b.A7}, {mone, &a.A11, &b.A6}}, []int{1, 1, 1, 1, 1, 1, 82, 82, 82, 82, 82, 82})
//
//	// d6  =  c6  + 18 * c12 + 242 * c18
//	//     =  a0 b6 + a1 b5 + a2 b4 + a3 b3 + a4 b2 + a5 b1 + a6 b0  + 18 * (a1 b11 + a2 b10 + a3 b9 + a4 b8 + a5 b7 + a6 b6 + a7 b5 + a8 b4 + a9 b3 + a10 b2 + a11 b1) + 242 * (a7 b11 + a8 b10 + a9 b9 + a10 b8 + a11 b7)
//	d6 := fr.Eval([][]*baseEl{{&a.A0, &b.A6}, {&a.A1, &b.A5}, {&a.A2, &b.A4}, {&a.A3, &b.A3}, {&a.A4, &b.A2}, {&a.A5, &b.A1}, {&a.A6, &b.A0}, {&a.A1, &b.A11}, {&a.A2, &b.A10}, {&a.A3, &b.A9}, {&a.A4, &b.A8}, {&a.A5, &b.A7}, {&a.A6, &b.A6}, {&a.A7, &b.A5}, {&a.A8, &b.A4}, {&a.A9, &b.A3}, {&a.A10, &b.A2}, {&a.A11, &b.A1}, {&a.A7, &b.A11}, {&a.A8, &b.A10}, {&a.A9, &b.A9}, {&a.A10, &b.A8}, {&a.A11, &b.A7}}, []int{1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 242, 242, 242, 242, 242})
//
//	// d7  =  c7  + 18 * c13 + 242 * c19
//	//     =  a0 b7 + a1 b6 + a2 b5 + a3 b4 + a4 b3 + a5 b2 + a6 b1 + a7 b0  + 18 * (a2 b11 + a3 b10 + a4 b9 + a5 b8 + a6 b7 + a7 b6 + a8 b5 + a9 b4 + a10 b3 + a11 b2) + 242 * (a8 b11 + a9 b10 + a10 b9 + a11 b8)
//	d7 := fr.Eval([][]*baseEl{{&a.A0, &b.A7}, {&a.A1, &b.A6}, {&a.A2, &b.A5}, {&a.A3, &b.A4}, {&a.A4, &b.A3}, {&a.A5, &b.A2}, {&a.A6, &b.A1}, {&a.A7, &b.A0}, {&a.A2, &b.A11}, {&a.A3, &b.A10}, {&a.A4, &b.A9}, {&a.A5, &b.A8}, {&a.A6, &b.A7}, {&a.A7, &b.A6}, {&a.A8, &b.A5}, {&a.A9, &b.A4}, {&a.A10, &b.A3}, {&a.A11, &b.A2}, {&a.A8, &b.A11}, {&a.A9, &b.A10}, {&a.A10, &b.A9}, {&a.A11, &b.A8}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 242, 242, 242, 242})
//
//	// d8  =  c8  + 18 * c14 + 242 * c20
//	//     =  a0 b8 + a1 b7 + a2 b6 + a3 b5 + a4 b4 + a5 b3 + a6 b2 + a7 b1 + a8 b0  + 18 * (a3 b11 + a4 b10 + a5 b9 + a6 b8 + a7 b7 + a8 b6 + a9 b5 + a10 b4 + a11 b3) + 242 * (a9 b11 + a10 b10 + a11 b9)
//	d8 := fr.Eval([][]*baseEl{{&a.A0, &b.A8}, {&a.A1, &b.A7}, {&a.A2, &b.A6}, {&a.A3, &b.A5}, {&a.A4, &b.A4}, {&a.A5, &b.A3}, {&a.A6, &b.A2}, {&a.A7, &b.A1}, {&a.A8, &b.A0}, {&a.A3, &b.A11}, {&a.A4, &b.A10}, {&a.A5, &b.A9}, {&a.A6, &b.A8}, {&a.A7, &b.A7}, {&a.A8, &b.A6}, {&a.A9, &b.A5}, {&a.A10, &b.A4}, {&a.A11, &b.A3}, {&a.A9, &b.A11}, {&a.A10, &b.A10}, {&a.A11, &b.A9}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 18, 18, 242, 242, 242})
//
//	// d9  =  c9  + 18 * c15 + 242 * c21
//	//     =  a0 b9 + a1 b8 + a2 b7 + a3 b6 + a4 b5 + a5 b4 + a6 b3 + a7 b2 + a8 b1 + a9 b0  + 18 * (a4 b11 + a5 b10 + a6 b9 + a7 b8 + a8 b7 + a9 b6 + a10 b5 + a11 b4) + 242 * (a10 b11 + a11 b10)
//	d9 := fr.Eval([][]*baseEl{{&a.A0, &b.A9}, {&a.A1, &b.A8}, {&a.A2, &b.A7}, {&a.A3, &b.A6}, {&a.A4, &b.A5}, {&a.A5, &b.A4}, {&a.A6, &b.A3}, {&a.A7, &b.A2}, {&a.A8, &b.A1}, {&a.A9, &b.A0}, {&a.A4, &b.A11}, {&a.A5, &b.A10}, {&a.A6, &b.A9}, {&a.A7, &b.A8}, {&a.A8, &b.A7}, {&a.A9, &b.A6}, {&a.A10, &b.A5}, {&a.A11, &b.A4}, {&a.A10, &b.A11}, {&a.A11, &b.A10}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 18, 242, 242})
//
//	// d10 =  c10 + 18 * c16 + 242 * c22
//	//     =  a0 b10 + a1 b9 + a2 b8 + a3 b7 + a4 b6 + a5 b5 + a6 b4 + a7 b3 + a8 b2 + a9 b1 + a10 b0 + 18 * (a5 b11 + a6 b10 + a7 b9 + a8 b8 + a9 b7 + a10 b6 + a11 b5) + 242 * (a11 b11)
//	d10 := fr.Eval([][]*baseEl{{&a.A0, &b.A10}, {&a.A1, &b.A9}, {&a.A2, &b.A8}, {&a.A3, &b.A7}, {&a.A4, &b.A6}, {&a.A5, &b.A5}, {&a.A6, &b.A4}, {&a.A7, &b.A3}, {&a.A8, &b.A2}, {&a.A9, &b.A1}, {&a.A10, &b.A0}, {&a.A5, &b.A11}, {&a.A6, &b.A10}, {&a.A7, &b.A9}, {&a.A8, &b.A8}, {&a.A9, &b.A7}, {&a.A10, &b.A6}, {&a.A11, &b.A5}, {&a.A11, &b.A11}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 242})
//
//	// d11 =  c11 + 18 * c17
//	//     =  a0 b11 + a1 b10 + a2 b9 + a3 b8 + a4 b7 + a5 b6 + a6 b5 + a7 b4 + a8 b3 + a9 b2 + a10 b1 + a11 b0 + 18 * (a6 b11 + a7 b10 + a8 b9 + a9 b8 + a10 b7 + a11 b6)
//	d11 := fr.Eval([][]*baseEl{{&a.A0, &b.A11}, {&a.A1, &b.A10}, {&a.A2, &b.A9}, {&a.A3, &b.A8}, {&a.A4, &b.A7}, {&a.A5, &b.A6}, {&a.A6, &b.A5}, {&a.A7, &b.A4}, {&a.A8, &b.A3}, {&a.A9, &b.A2}, {&a.A10, &b.A1}, {&a.A11, &b.A0}, {&a.A6, &b.A11}, {&a.A7, &b.A10}, {&a.A8, &b.A9}, {&a.A9, &b.A8}, {&a.A10, &b.A7}, {&a.A11, &b.A6}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18})
//
//	return &E12{
//		A0:  *d0,
//		A1:  *d1,
//		A2:  *d2,
//		A3:  *d3,
//		A4:  *d4,
//		A5:  *d5,
//		A6:  *d6,
//		A7:  *d7,
//		A8:  *d8,
//		A9:  *d9,
//		A10: *d10,
//		A11: *d11,
//	}
//}
