package uniform

import (
	"fmt"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254Fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
	"math/big"
	"testing"
)

func TestGtMul(t *testing.T) {
	var gtMulCircuit GTMul
	var one fr.Element
	one.SetOne()
	var random fr.Element
	_, _ = random.SetRandom()

	var rPowers [13]fr.Element
	rPowers[0] = one
	for i := 1; i < 13; i++ {
		rPowers[i].Mul(&random, &rPowers[i-1])
	}
	reduciblePoly := make([]fr.Element, 13) // degree 12 polynomial has 13 coefficients
	reduciblePoly[0].SetInt64(82)           // constant term
	reduciblePoly[6].SetInt64(-18)          // coefficient of x^6
	reduciblePoly[12].SetOne()              // coefficient of x^12

	DivisorEval := fr.Element{}
	for i := 0; i < len(reduciblePoly); i++ {
		var temp fr.Element
		temp.Mul(&reduciblePoly[i], &rPowers[i])
		DivisorEval.Add(&DivisorEval, &temp)
	}

	gtMulCircuit = GTMul{
		rPowers:     rPowers,
		DivisorEval: DivisorEval,
	}
	gtMulConstraints, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &gtMulCircuit)

	var in1Tower, in2Tower, in1in2Tower bn254.E12
	_, _ = in1Tower.SetRandom()
	_, _ = in2Tower.SetRandom()
	in1in2Tower.Mul(&in1Tower, &in2Tower)

	in1 := FromE12(&in1Tower)
	in2 := FromE12(&in2Tower)
	in1in2 := FromE12(&in1in2Tower)

	println("no of constraints are ", gtMulConstraints.GetNbConstraints())
	in1in2Poly := multiplyPolynomials(in1, in2)

	quotient := computeQuotientPoly(in1in2Poly, reduciblePoly, in1in2)
	assignment := &GTMul{
		Acc:  [12]frontend.Variable(makeFrontendVariable(in1)),
		In:   [12]frontend.Variable(makeFrontendVariable(in2)),
		Quot: [11]frontend.Variable(makeFrontendVariable(quotient)),
		Rem:  [12]frontend.Variable(makeFrontendVariable(in1in2)),
	}

	witness, err := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	wit, _ := gtMulConstraints.Solve(witness)
	witnessVec := wit.(*cs.R1CSSolution).W
	println("Len of witness is ", len(witnessVec))
}

func TestGTExp(t *testing.T) {
	var inTower bn254.E12
	_, _ = inTower.SetRandom()

	var one fr.Element
	one.SetOne()

	var exp bn254Fp.Element
	_, _ = exp.SetRandom()
	var frBigInt big.Int

	exp.BigInt(&frBigInt)
	var random fr.Element
	_, _ = random.SetRandom()

	var rPowers [13]fr.Element
	rPowers[0] = one
	for i := 1; i < 13; i++ {
		rPowers[i].Mul(&random, &rPowers[i-1])
	}

	gtExpCircuit := GTExp{
		base:    inTower,
		rPowers: rPowers,
		exp:     frBigInt,
	}

	gtExpR1Cs := gtExpCircuit.CreateStepCircuit()
	fmt.Println("No of Constraints ", gtExpR1Cs.GetNbConstraints())
	gtExpCircuit.GenerateWitness(gtExpR1Cs)
}

func TestComputeQuotientPoly(t *testing.T) {
	// Create test polynomials - use a simpler example first
	// f(x) = x^2 + 3x + 2 = (x + 1)(x + 2)
	// d(x) = x + 1
	// r(x) = 0 (no remainder)
	// Expected quotient: q(x) = x + 2

	f := make([]fr.Element, 3)
	f[0].SetInt64(2) // constant term
	f[1].SetInt64(3) // coefficient of x
	f[2].SetInt64(1) // coefficient of x^2

	d := make([]fr.Element, 2)
	d[0].SetInt64(1) // constant term
	d[1].SetInt64(1) // coefficient of x

	r := make([]fr.Element, 1)
	r[0].SetInt64(0) // remainder is 0

	quotient := computeQuotientPoly(f, d, r)

	// Debug output
	t.Logf("f coefficients: %v %v %v", f[0], f[1], f[2])
	t.Logf("d coefficients: %v %v", d[0], d[1])
	t.Logf("r coefficients: %v", r[0])
	t.Logf("quotient length: %d", len(quotient))
	for i, coeff := range quotient {
		t.Logf("quotient[%d]: %v", i, coeff)
	}

	// Verify the length of the quotient
	expectedLen := len(f) - len(d) + 1
	if len(quotient) != expectedLen {
		t.Errorf("Expected quotient length %d, got %d", expectedLen, len(quotient))
	}

	// Expected quotient coefficients for q(x) = x + 2: [2, 1]
	var expectedConst, expectedLinear fr.Element
	expectedConst.SetInt64(2)
	expectedLinear.SetInt64(1)

	if len(quotient) >= 1 && !quotient[0].Equal(&expectedConst) {
		t.Errorf("Expected constant term %v, got %v", expectedConst, quotient[0])
	}
	if len(quotient) >= 2 && !quotient[1].Equal(&expectedLinear) {
		t.Errorf("Expected coefficient of x %v, got %v", expectedLinear, quotient[1])
	}

	// Verify that f - r = d * q
	product := multiplyPolynomials(d, quotient)
	t.Logf("Product d*q has %d coefficients", len(product))
	for i, coeff := range product {
		t.Logf("product[%d]: %v", i, coeff)
	}

	// Compute f - r
	fMinusR := make([]fr.Element, len(f))
	copy(fMinusR, f)
	for i := 0; i < len(r) && i < len(fMinusR); i++ {
		fMinusR[i].Sub(&fMinusR[i], &r[i])
	}

	t.Logf("f-r has %d coefficients", len(fMinusR))
	for i, coeff := range fMinusR {
		t.Logf("fMinusR[%d]: %v", i, coeff)
	}

	// Compare coefficients
	maxLen := len(product)
	if len(fMinusR) > maxLen {
		maxLen = len(fMinusR)
	}

	for i := 0; i < maxLen; i++ {
		var prodVal, fMinusRVal fr.Element
		if i < len(product) {
			prodVal = product[i]
		}
		if i < len(fMinusR) {
			fMinusRVal = fMinusR[i]
		}
		if !prodVal.Equal(&fMinusRVal) {
			t.Errorf("Polynomial division identity failed at degree %d: expected %v, got %v",
				i, fMinusRVal, prodVal)
		}
	}
}
