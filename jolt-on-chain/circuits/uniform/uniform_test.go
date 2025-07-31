package uniform

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254Fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"

	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
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
		Acc:  [12]frontend.Variable(utils.MakeFrontendVariable(in1)),
		In:   [12]frontend.Variable(utils.MakeFrontendVariable(in2)),
		Quot: [11]frontend.Variable(utils.MakeFrontendVariable(quotient)),
		Rem:  [12]frontend.Variable(utils.MakeFrontendVariable(in1in2)),
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
	// expectedLen := len(f) - len(d) + 1
	// if len(quotient) != expectedLen {
	// 	t.Errorf("Expected quotient length %d, got %d", expectedLen, len(quotient))
	// }

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

func TestToTower(t *testing.T) {
	var inTower bn254.E12
	_, _ = inTower.SetRandom()
	in1 := FromE12(&inTower)
	in_tower_from_func := ToTower(in1)
	res := inTower.Equal(&in_tower_from_func)
	if !res {
		fmt.Println("Final result mismatch")
	}

}

func TestGTMultiMul(t *testing.T) {
	var in1Tower, in2Tower bn254.E12
	_, _ = in1Tower.SetRandom()
	_, _ = in2Tower.SetRandom()

	var one fr.Element
	one.SetOne()

	var random fr.Element
	_, _ = random.SetRandom()

	var rPowers [13]fr.Element
	rPowers[0] = one
	for i := 1; i < 13; i++ {
		rPowers[i].Mul(&random, &rPowers[i-1])
	}

	// Change the constant  according to number of multiplications
	n := 10
	inTowerArr := make([]bn254.E12, n)
	for i := 0; i < n; i++ {
		_, _ = inTowerArr[i].SetRandom()
	}

	inTowervalue := make([][]fr.Element, n)
	for i := 0; i < n; i++ {
		inTowervalue[i] = FromE12(&inTowerArr[i])
	}

	var out_res bn254.E12
	out_res.SetOne()
	for i := 0; i < n; i++ {
		out_res.Mul(&out_res, &inTowerArr[i])
	}

	out_val := FromE12(&out_res)

	gtmultimulCircuit := GTMultiMul{
		in:      inTowervalue,
		rPowers: rPowers,
		out:     out_val,
	}

	gtmultimulR1Cs := gtmultimulCircuit.CreateStepCircuit()
	fmt.Println("No of Constraints ", gtmultimulR1Cs.GetNbConstraints())
	gtmultimulCircuit.GenerateWitness(gtmultimulR1Cs)
}

func TestMSM(t *testing.T) {

	var one fr.Element
	one.SetOne()
	var random fr.Element
	_, _ = random.SetRandom()

	var rPowers [13]fr.Element
	rPowers[0] = one
	for i := 1; i < 13; i++ {
		rPowers[i].Mul(&random, &rPowers[i-1])
	}

	n := 50
	basesArr := make([]bn254.E12, n)
	for i := 0; i < n; i++ {
		_, _ = basesArr[i].SetRandom()
	}

	basesArrvalue := make([][]fr.Element, n)
	for i := 0; i < n; i++ {
		basesArrvalue[i] = FromE12(&basesArr[i])
	}

	powers := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		powers[i].SetRandom()
	}

	powersBigInt := make([]big.Int, n)

	for i := 0; i < n; i++ {
		powers[i].BigInt(&powersBigInt[i])
	}

	var out_res bn254.E12
	out_res.SetOne()
	gt_exp := make([]bn254.E12, n)

	for i := 0; i < n; i++ {
		gt_exp[i].Exp(basesArr[i], &powersBigInt[i])
		out_res.Mul(&out_res, &gt_exp[i])
	}

	msmCircuit := MSM{
		bases:      basesArrvalue,
		rPowers:    rPowers,
		powers:     powersBigInt,
		out:        FromE12(&out_res),
		gtExp:      &GTExp{},
		gtMultiMul: &GTMultiMul{},
	}

	msmR1Cs := msmCircuit.CreateStepCircuits()
	// fmt.Println("No of Constraints in exp ", msmCircuit.GetConstraints())
	msmCircuit.GenerateWitness(msmR1Cs)

}

func TestG1MulCircuit(t *testing.T) {

	// Base G1 point
	base := groups.RandomG1Affine()

	var exp big.Int
	// Generate exactly 128 random bits:
	buf := make([]byte, 16) // 16 bytes = 128 bits
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	exp.SetBytes(buf)

	// Scalar exp
	var expected bn254.G1Affine
	expected.ScalarMultiplication(&base, &exp)

	gmul := G1Mul{
		Base: groups.FromG1Affine(&base),
		Exp:  exp,
		Step: &G1MulStep{},
	}

	// Compile single step circuit
	r1cs := gmul.CreateStepCircuit()

	// Generate full witness
	witness := gmul.GenerateWitness(r1cs)

	var res_from_witness groups.G1Projective
	res_from_witness.X = witness[5090]
	res_from_witness.Y = witness[5091]
	res_from_witness.Z = witness[5092]

	// Compare witness with expected
	if res_from_witness != groups.FromG1Affine(&expected) {
		fmt.Println("Witness is not equal to expected")
	}

	fmt.Println("✅ G1 scalar mul test passed")

}

func TestG2MulCircuit(t *testing.T) {
	// Random base G2 point
	var base bn254.G2Affine
	_, base = groups.RandomG1G2Affines()

	// Random scalar exponent
	var exp big.Int
	// Generate exactly 128 random bits:
	buf := make([]byte, 16) // 16 bytes = 128 bits
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	exp.SetBytes(buf)

	// Native expected output
	var expected bn254.G2Affine
	expected.ScalarMultiplication(&base, &exp)

	var bn254_fr_exp bn254_fr.Element
	bn254_fr_exp.SetBigInt(&exp)

	// Build the step-by-step G2Mul circuit
	gmul := &G2Mul{
		Base: groups.FromBNG2Affine(&base),
		Exp:  bn254_fr_exp,
	}

	fmt.Println("Compiling G2Mul step circuit...")

	r1cs := gmul.CreateStepCircuit()

	fmt.Println("Number of constraints per step:", r1cs.GetNbConstraints())

	// Generate full witness by stepping
	witness := gmul.GenerateWitness(r1cs)

	var res_from_witness groups.G2Projective
	res_from_witness.X.A0 = witness[13605]
	res_from_witness.X.A1 = witness[13606]

	res_from_witness.Y.A0 = witness[13607]
	res_from_witness.Y.A1 = witness[13608]

	res_from_witness.Z.A0 = witness[13609]
	res_from_witness.Z.A1 = witness[13610]

	// Compare witness with expected
	if res_from_witness != groups.FromBNG2Affine(&expected) {
		fmt.Println("Witness is not equal to expected")
	}

	fmt.Println("✅ G2 scalar mul test passed")
}

func TestG1MultiMul(t *testing.T) {
	// Random base points
	E1_Beta := groups.RandomG1Affine()
	E1_Plus := groups.RandomG1Affine()
	expected_E1_Minus := groups.RandomG1Affine()
	Gamma1 := groups.RandomG1Affine()

	// Random alpha and beta
	var alpha, beta, d big.Int
	alphaBytes := make([]byte, 16)
	betaBytes := make([]byte, 16)
	dbytes := make([]byte, 16)
	rand.Read(alphaBytes)
	rand.Read(betaBytes)
	rand.Read(dbytes)

	alpha.SetBytes(alphaBytes)
	beta.SetBytes(betaBytes)
	d.SetBytes(dbytes)

	// Compute expected results using native scalar mul
	var expected_Beta_E1_Beta bn254.G1Affine
	var expected_Alpha_E1_Plus bn254.G1Affine
	var alphaInvE1_Minus bn254.G1Affine
	var expected_d_Gamma1 bn254.G1Affine

	expected_Beta_E1_Beta.ScalarMultiplication(&E1_Beta, &beta)
	expected_Alpha_E1_Plus.ScalarMultiplication(&E1_Plus, &alpha)
	expected_d_Gamma1.ScalarMultiplication(&Gamma1, &d)
	// alpha^-1 mod r
	alphaInv := new(big.Int).ModInverse(&alpha, bn254_fr.Modulus())
	alphaInvE1_Minus.ScalarMultiplication(&expected_E1_Minus, alphaInv)

	// Setup the circuit
	circuit := &G1MultiMul{
		Alpha:              []frontend.Variable{alpha},
		Beta:               []frontend.Variable{beta},
		D:                  d,
		E1_Beta:            []groups.G1Projective{groups.FromG1Affine(&E1_Beta)},
		E1_Plus:            []groups.G1Projective{groups.FromG1Affine(&E1_Plus)},
		Alpha_Inv_E1_Minus: []groups.G1Projective{groups.FromG1Affine(&alphaInvE1_Minus)},
		Gamma1:             groups.FromG1Affine(&Gamma1),
		// dGamma1Out:         groups.FromG1Affine(&expected_d_Gamma1),
		Step: &G1MulStep{},
	}

	// Compile the step circuit
	r1cs := circuit.CreateStepCircuit()

	// Generate full witness
	witness := circuit.GenerateWitness(r1cs)

	var beta_e1_beta_from_witness groups.G1Projective

	beta_e1_beta_from_witness.X = witness[5090]
	beta_e1_beta_from_witness.Y = witness[5091]
	beta_e1_beta_from_witness.Z = witness[5092]

	// Compare beta_e1_beta_from_witness and expected_Beta_E1_Beta
	if beta_e1_beta_from_witness != groups.FromG1Affine(&expected_Beta_E1_Beta) {
		fmt.Println("beta_e1_beta_from_witness is not equal to expected_Beta_E1_Beta")
	}

	var alpha_e1_plus_from_witness groups.G1Projective

	alpha_e1_plus_from_witness.X = witness[10210]
	alpha_e1_plus_from_witness.Y = witness[10211]
	alpha_e1_plus_from_witness.Z = witness[10212]

	if alpha_e1_plus_from_witness != groups.FromG1Affine(&expected_Alpha_E1_Plus) {
		fmt.Println("alpha_e1_plus_from_witness is not equal to expected_Alpha_E1_Plus")
	}

	var E1_minus_from_witness groups.G1Projective

	E1_minus_from_witness.X = witness[15330]
	E1_minus_from_witness.Y = witness[15331]
	E1_minus_from_witness.Z = witness[15332]

	if E1_minus_from_witness != groups.FromG1Affine(&expected_E1_Minus) {
		fmt.Println("E1_minus__from_witness is not equal to expected_E1_Minus")
	}

	var d_Gamma1_from_witness groups.G1Projective

	d_Gamma1_from_witness.X = witness[20450]
	d_Gamma1_from_witness.Y = witness[20451]
	d_Gamma1_from_witness.Z = witness[20452]

	if d_Gamma1_from_witness != circuit.dGamma1Out {
		fmt.Println("d_Gamma1_from_witness is not equal to dGamma1Out")
	}
	if d_Gamma1_from_witness != groups.FromG1Affine(&expected_d_Gamma1) {
		fmt.Println("d_Gamma1_from_witness is not equal to expected_d_Gamma1")
	}
}

func TestG1MultiMulMatrix(t *testing.T) {
	// Random base points
	E1_Beta := groups.RandomG1Affine()
	E1_Plus := groups.RandomG1Affine()
	expected_E1_Minus := groups.RandomG1Affine()
	Gamma1 := groups.RandomG1Affine()

	// Random alpha and beta
	var alpha, beta, d big.Int
	alphaBytes := make([]byte, 16)
	betaBytes := make([]byte, 16)
	dbytes := make([]byte, 16)
	rand.Read(alphaBytes)
	rand.Read(betaBytes)
	rand.Read(dbytes)

	alpha.SetBytes(alphaBytes)
	beta.SetBytes(betaBytes)
	d.SetBytes(dbytes)

	// Compute expected results using native scalar mul
	var expected_Beta_E1_Beta bn254.G1Affine
	var expected_Alpha_E1_Plus bn254.G1Affine
	var alphaInvE1_Minus bn254.G1Affine
	var expected_d_Gamma1 bn254.G1Affine

	expected_Beta_E1_Beta.ScalarMultiplication(&E1_Beta, &beta)
	expected_Alpha_E1_Plus.ScalarMultiplication(&E1_Plus, &alpha)
	expected_d_Gamma1.ScalarMultiplication(&Gamma1, &d)
	// alpha^-1 mod r
	alphaInv := new(big.Int).ModInverse(&alpha, bn254_fr.Modulus())
	alphaInvE1_Minus.ScalarMultiplication(&expected_E1_Minus, alphaInv)

	// Setup the circuit
	circuit := &G1MultiMul{
		Alpha:              []frontend.Variable{alpha},
		Beta:               []frontend.Variable{beta},
		D:                  d,
		E1_Beta:            []groups.G1Projective{groups.FromG1Affine(&E1_Beta)},
		E1_Plus:            []groups.G1Projective{groups.FromG1Affine(&E1_Plus)},
		Alpha_Inv_E1_Minus: []groups.G1Projective{groups.FromG1Affine(&alphaInvE1_Minus)},
		Gamma1:             groups.FromG1Affine(&Gamma1),
		// dGamma1Out:         groups.FromG1Affine(&expected_d_Gamma1),
		Step: &G1MulStep{},
	}

	PrintR1CSStatsG1MultiMul(circuit)
}

func PrintR1CSStatsG1MultiMul(g *G1MultiMul) {
	r1csInfo := g.GetConstraints()

	// generate full witness
	stepCS := g.CreateStepCircuit()
	witness := g.GenerateWitness(stepCS)
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

func TestG2MultiMul(t *testing.T) {
	// Random base points
	_, E2_Beta := groups.RandomG1G2Affines()
	_, E2_Plus := groups.RandomG1G2Affines()
	_, expected_E2_Minus := groups.RandomG1G2Affines()
	_, ExpectedGamma2 := groups.RandomG1G2Affines()

	// Random alpha and beta (128-bit)
	var alpha, beta, d big.Int
	alphaBytes := make([]byte, 16)
	betaBytes := make([]byte, 16)
	dbytes := make([]byte, 16)

	rand.Read(alphaBytes)
	rand.Read(betaBytes)
	rand.Read(dbytes)

	alpha.SetBytes(alphaBytes)
	beta.SetBytes(betaBytes)
	d.SetBytes(dbytes)

	// Compute expected results using native scalar mul
	var expected_Beta_E2_Beta bn254.G2Affine
	var expected_Alpha_E2_Plus bn254.G2Affine
	var alphaInvE2_Minus bn254.G2Affine
	var dInvGamma2 bn254.G2Affine

	expected_Beta_E2_Beta.ScalarMultiplication(&E2_Beta, &beta)
	expected_Alpha_E2_Plus.ScalarMultiplication(&E2_Plus, &alpha)

	// alpha^-1 mod r
	alphaInv := new(big.Int).ModInverse(&alpha, bn254_fr.Modulus())
	dInv := new(big.Int).ModInverse(&d, bn254_fr.Modulus())

	alphaInvE2_Minus.ScalarMultiplication(&expected_E2_Minus, alphaInv)
	dInvGamma2.ScalarMultiplication(&ExpectedGamma2, dInv)

	// Setup the circuit
	circuit := &G2MultiMul{
		Alpha:              []frontend.Variable{alpha},
		Beta:               []frontend.Variable{beta},
		E2_Beta:            []groups.G2Projective{groups.FromBNG2Affine(&E2_Beta)},
		E2_Plus:            []groups.G2Projective{groups.FromBNG2Affine(&E2_Plus)},
		Alpha_Inv_E2_Minus: []groups.G2Projective{groups.FromBNG2Affine(&alphaInvE2_Minus)},
		D:                  d,
		Gamma2Out:          groups.FromBNG2Affine(&ExpectedGamma2),
		DInvGamma2:         groups.FromBNG2Affine(&dInvGamma2),
		Step:               &G2MulStep{},
	}

	// Compile the step circuit
	r1cs := circuit.CreateStepCircuit()

	// Generate full witness
	witness := circuit.GenerateWitness(r1cs)

	var beta_e2_beta_from_witness groups.G2Projective
	beta_e2_beta_from_witness.X.A0 = witness[13605]
	beta_e2_beta_from_witness.X.A1 = witness[13606]
	beta_e2_beta_from_witness.Y.A0 = witness[13607]
	beta_e2_beta_from_witness.Y.A1 = witness[13608]
	beta_e2_beta_from_witness.Z.A0 = witness[13609]
	beta_e2_beta_from_witness.Z.A1 = witness[13610]

	if beta_e2_beta_from_witness != groups.FromBNG2Affine(&expected_Beta_E2_Beta) {
		panic("beta_e2_beta_from_witness is not equal to expected_Beta_E2_Beta")
	}

	// construct G2Projective from witness
	var alpha_e2_plus_from_witness groups.G2Projective
	alpha_e2_plus_from_witness.X.A0 = witness[27301]
	alpha_e2_plus_from_witness.X.A1 = witness[27302]
	alpha_e2_plus_from_witness.Y.A0 = witness[27303]
	alpha_e2_plus_from_witness.Y.A1 = witness[27304]
	alpha_e2_plus_from_witness.Z.A0 = witness[27305]
	alpha_e2_plus_from_witness.Z.A1 = witness[27306]

	if alpha_e2_plus_from_witness != groups.FromBNG2Affine(&expected_Alpha_E2_Plus) {
		panic("alpha_e2_plus_from_witness is not equal to expected_Alpha_E2_Plus")
	}

	var E2_minus_from_witness groups.G2Projective
	E2_minus_from_witness.X.A0 = witness[40997]
	E2_minus_from_witness.X.A1 = witness[40998]
	E2_minus_from_witness.Y.A0 = witness[40999]
	E2_minus_from_witness.Y.A1 = witness[41000]
	E2_minus_from_witness.Z.A0 = witness[41001]
	E2_minus_from_witness.Z.A1 = witness[41002]

	if E2_minus_from_witness != groups.FromBNG2Affine(&expected_E2_Minus) {
		panic("E2_minus_from_witness is not equal to alphaInvE2_Minus")
	}

	var ExpectedGamma2fromWitness groups.G2Projective
	ExpectedGamma2fromWitness.X.A0 = witness[54693]
	ExpectedGamma2fromWitness.X.A1 = witness[54694]
	ExpectedGamma2fromWitness.Y.A0 = witness[54695]
	ExpectedGamma2fromWitness.Y.A1 = witness[54696]
	ExpectedGamma2fromWitness.Z.A0 = witness[54697]
	ExpectedGamma2fromWitness.Z.A1 = witness[54698]

	if ExpectedGamma2fromWitness != groups.FromBNG2Affine(&ExpectedGamma2) {
		panic("ExpectedGamma2fromWitness is not equal to ExpectedGamma2")
	}
}


func PrintR1CSStatsG2MultiMul(g *G2MultiMul) {
	r1csInfo := g.GetConstraints()

	// generate full witness
	stepCS := g.CreateStepCircuit()
	witness := g.GenerateWitness(stepCS)
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


func TestG2MultiMulMatrix(t *testing.T) {
	// Random base points
	_, E2_Beta := groups.RandomG1G2Affines()
	_, E2_Plus := groups.RandomG1G2Affines()
	_, expected_E2_Minus := groups.RandomG1G2Affines()
	_, ExpectedGamma2 := groups.RandomG1G2Affines()

	// Random alpha and beta (128-bit)
	var alpha, beta, d big.Int
	alphaBytes := make([]byte, 16)
	betaBytes := make([]byte, 16)
	dbytes := make([]byte, 16)

	rand.Read(alphaBytes)
	rand.Read(betaBytes)
	rand.Read(dbytes)

	alpha.SetBytes(alphaBytes)
	beta.SetBytes(betaBytes)
	d.SetBytes(dbytes)

	// Compute expected results using native scalar mul
	var expected_Beta_E2_Beta bn254.G2Affine
	var expected_Alpha_E2_Plus bn254.G2Affine
	var alphaInvE2_Minus bn254.G2Affine
	var dInvGamma2 bn254.G2Affine

	expected_Beta_E2_Beta.ScalarMultiplication(&E2_Beta, &beta)
	expected_Alpha_E2_Plus.ScalarMultiplication(&E2_Plus, &alpha)

	// alpha^-1 mod r
	alphaInv := new(big.Int).ModInverse(&alpha, bn254_fr.Modulus())
	dInv := new(big.Int).ModInverse(&d, bn254_fr.Modulus())

	alphaInvE2_Minus.ScalarMultiplication(&expected_E2_Minus, alphaInv)
	dInvGamma2.ScalarMultiplication(&ExpectedGamma2, dInv)

	// Setup the circuit
	circuit := &G2MultiMul{
		Alpha:              []frontend.Variable{alpha},
		Beta:               []frontend.Variable{beta},
		E2_Beta:            []groups.G2Projective{groups.FromBNG2Affine(&E2_Beta)},
		E2_Plus:            []groups.G2Projective{groups.FromBNG2Affine(&E2_Plus)},
		Alpha_Inv_E2_Minus: []groups.G2Projective{groups.FromBNG2Affine(&alphaInvE2_Minus)},
		D:                  d,
		Gamma2Out:          groups.FromBNG2Affine(&ExpectedGamma2),
		DInvGamma2:         groups.FromBNG2Affine(&dInvGamma2),
		Step:               &G2MulStep{},
	}
	PrintR1CSStatsG2MultiMul(circuit)
}
