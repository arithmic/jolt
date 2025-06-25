package pairing

import (
	"fmt"
	"math/big"

	"github.com/arithmic/gnark/constraint"
	"github.com/arithmic/gnark/frontend"

	cs "github.com/arithmic/gnark/constraint/grumpkin"

	"github.com/arithmic/gnark/frontend/cs/r1cs"

	field_tower "github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"
	groups "github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/groups"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func ExpByNegX(e12 *field_tower.Ext12, x *field_tower.Fp12) *field_tower.Fp12 {

	bits := []int{
		1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1,
	}

	z := e12.One()
	// Perform binary exponentiation
	for i := 0; i < len(bits); i++ {

		// Square z
		z = e12.Square(z)

		// Conditionally multiply z by x if the current bit is 1
		if bits[i] == 1 {
			z = e12.Mul(z, x)
		}
	}
	res := e12.Conjugate(z)
	return res

}

func Gamma1(e2 *field_tower.Ext2) [6]field_tower.Fp2 {
	var gamma1 [6]field_tower.Fp2
	// Define the constant shi = (9, 1)
	shi := field_tower.Fp2{
		A0: frontend.Variable(9),
		A1: frontend.Variable(1),
	}

	constExp, _ := new(big.Int).SetString("3648040478639879203707734290876212514782718526216303943781506315774204368097", 10)

	constExpVar := frontend.Variable(*constExp)
	shiC := e2.Exp(&shi, &constExpVar)

	// Initialize gamma1[0] = (1, 0)
	gamma1[0] = *e2.One()

	// Compute gamma1[i] = gamma1[i-1] * shi_c for i = 1 to 5
	for i := 1; i <= 5; i++ {
		gamma1[i] = *e2.Mul(&gamma1[i-1], shiC)
	}

	return gamma1
}

func Gamma2(e2 *field_tower.Ext2, gamma1 [6]field_tower.Fp2) [6]field_tower.Fp2 {
	var gamma2 [6]field_tower.Fp2

	// Compute gamma2[i] = gamma1[i] * Fp2conjugate()(gamma1[i]) for i = 1 to 5
	for i := 1; i <= 5; i++ {
		// Compute the conjugate of gamma1[i]
		gamma1Conjugate := e2.Conjugate(&gamma1[i])

		// Multiply gamma1[i] with its conjugate
		gamma2[i] = *e2.Mul(&gamma1[i], gamma1Conjugate)
	}

	return gamma2
}

func Gamma3(e2 *field_tower.Ext2, gamma1 [6]field_tower.Fp2, gamma2 [6]field_tower.Fp2) [6]field_tower.Fp2 {
	var gamma3 [6]field_tower.Fp2

	// Compute gamma3[i] = gamma1[i] * gamma2[i] for i = 1 to 5
	for i := 1; i <= 5; i++ {
		gamma3[i] = *e2.Mul(&gamma1[i], &gamma2[i])
	}

	return gamma3
}

// Computes Frobenius(x)
func Frobenius(e2 *field_tower.Ext2, x *field_tower.Fp12) *field_tower.Fp12 {

	var t [7]field_tower.Fp2
	var u [7]field_tower.Fp2

	// Compute conjugates of x components
	t[1] = *e2.Conjugate(&x.A0.A0)
	t[2] = *e2.Conjugate(&x.A1.A0)
	t[3] = *e2.Conjugate(&x.A0.A1)
	t[4] = *e2.Conjugate(&x.A1.A1)
	t[5] = *e2.Conjugate(&x.A0.A2)
	t[6] = *e2.Conjugate(&x.A1.A2)

	// Compute gamma1
	gamma1 := Gamma1(e2)

	// Compute u[i] = t[i] * gamma1[i-1] for i = 2 to 6
	for i := 2; i <= 6; i++ {
		u[i] = *e2.Mul(&t[i], &gamma1[i-1])
	}

	// Construct a0 and a1
	a0 := field_tower.Fp6{
		A0: t[1],
		A1: u[3],
		A2: u[5],
	}
	a1 := field_tower.Fp6{
		A0: u[2],
		A1: u[4],
		A2: u[6],
	}

	// Construct the output Fp12 element
	res := field_tower.Fp12{
		A0: a0,
		A1: a1,
	}

	return &res

}

// Computes Frobenius^2(x)
func FrobeniusSquare(e2 *field_tower.Ext2, x *field_tower.Fp12) *field_tower.Fp12 {

	// Compute gamma1
	gamma1 := Gamma1(e2)

	// Compute gamma2 using gamma1
	gamma2 := Gamma2(e2, gamma1)

	// Compute intermediate values u2, u3, u4, u5, u6
	u2 := *e2.Mul(&x.A1.A0, &gamma2[1])
	u3 := *e2.Mul(&x.A0.A1, &gamma2[2])
	u4 := *e2.Mul(&x.A1.A1, &gamma2[3])
	u5 := *e2.Mul(&x.A0.A2, &gamma2[4])
	u6 := *e2.Mul(&x.A1.A2, &gamma2[5])

	// Construct a0 and a1
	a0 := field_tower.Fp6{
		A0: x.A0.A0,
		A1: u3,
		A2: u5,
	}
	a1 := field_tower.Fp6{
		A0: u2,
		A1: u4,
		A2: u6,
	}
	// Construct the output Fp12 element
	res := field_tower.Fp12{
		A0: a0,
		A1: a1,
	}

	return &res
}

// Computes Frobenius^3(x)
func FrobeniusCube(e2 *field_tower.Ext2, x *field_tower.Fp12) *field_tower.Fp12 {

	var t [7]field_tower.Fp2
	var u [7]field_tower.Fp2

	// Compute conjugates of x components
	t[1] = *e2.Conjugate(&x.A0.A0)
	t[2] = *e2.Conjugate(&x.A1.A0)
	t[3] = *e2.Conjugate(&x.A0.A1)
	t[4] = *e2.Conjugate(&x.A1.A1)
	t[5] = *e2.Conjugate(&x.A0.A2)
	t[6] = *e2.Conjugate(&x.A1.A2)

	// Compute gamma1
	gamma1 := Gamma1(e2)

	// Compute gamma2 using gamma1
	gamma2 := Gamma2(e2, gamma1)

	// Compute gamma3 using gamma1 and gamma2
	gamma3 := Gamma3(e2, gamma1, gamma2)

	// Compute u[i] = t[i] * gamma3[i-1] for i = 2 to 6
	for i := 2; i <= 6; i++ {
		u[i] = *e2.Mul(&t[i], &gamma3[i-1])
	}

	// Construct a0 and a1
	a0 := field_tower.Fp6{
		A0: t[1],
		A1: u[3],
		A2: u[5],
	}
	a1 := field_tower.Fp6{
		A0: u[2],
		A1: u[4],
		A2: u[6],
	}

	// Construct the output Fp12 element
	res := field_tower.Fp12{
		A0: a0,
		A1: a1,
	}

	return &res
}

// Computes the multiplication of an Fp12 element by a sparse element of the form (c0, 0, 0, c3, c4, 0).
// This optimization leverages the sparsity of the multiplier to reduce the number of operations required.
func MulBy034(e2 *field_tower.Ext2, e6 *field_tower.Ext6, x *field_tower.Fp12, c0, c3, c4 *field_tower.Fp2) *field_tower.Fp12 {

	// Compute a.x, a.y, a.z
	a := field_tower.Fp6{
		A1: *e2.Mul(&x.A0.A1, c0),
		A0: *e2.Mul(&x.A0.A0, c0),
		A2: *e2.Mul(&x.A0.A2, c0),
	}

	b := MulBy01(e2, &x.A1, c3, c4)

	c0_new := e2.Add(c0, c3)

	temp_e := e6.Add(&x.A0, &x.A1)

	e_result := MulBy01(e2, temp_e, c0_new, c4)

	updated_y := e6.Sub(e_result, e6.Add(&a, b))

	temp := e6.MulByNonResidue(b)

	updated_x := e6.Add(temp, &a)

	updated_f := field_tower.Fp12{
		A0: *updated_x,
		A1: *updated_y,
	}

	return &updated_f
}

// Computes the multiplication of an Fp6 element by a sparse element of the form (c0, c1, 0).
func MulBy01(e2 *field_tower.Ext2, b *field_tower.Fp6, c0, c1 *field_tower.Fp2) *field_tower.Fp6 {

	a_a := e2.Mul(&b.A0, c0)

	b_b := e2.Mul(&b.A1, c1)

	// Compute t1
	tmp1 := e2.Add(&b.A1, &b.A2)
	tmp2 := e2.Mul(tmp1, c1)
	tmp3 := e2.Sub(tmp2, b_b)
	tmp4 := e2.MulByNonResidue(tmp3)
	t1 := e2.Add(tmp4, a_a)

	// Compute t3
	tmp5 := e2.Add(&b.A0, &b.A2)
	tmp6 := e2.Mul(tmp5, c0)
	tmp7 := e2.Sub(tmp6, a_a)
	t3 := e2.Add(tmp7, b_b)

	// Compute t2
	tmp8 := e2.Add(c0, c1)
	tmp9 := e2.Add(&b.A0, &b.A1)
	tmp10 := e2.Mul(tmp8, tmp9)
	tmp11 := e2.Sub(tmp10, a_a)
	t2 := e2.Sub(tmp11, b_b)

	// Construct the output Fp6 element
	res := field_tower.Fp6{
		A0: *t1,
		A1: *t2,
		A2: *t3,
	}

	return &res
}

// FinalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ
// where d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// we use instead d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// where s is the cofactor 2x₀(6x₀²+3x₀+1)
func FinalExp(e2 *field_tower.Ext2, e12 *field_tower.Ext12, x *field_tower.Fp12) *field_tower.Fp12 {

	// Easy part
	f1 := e12.Conjugate(x)
	f2 := e12.Inverse(x)
	f3 := e12.Mul(f1, f2)
	f4 := FrobeniusSquare(e2, f3)
	r := e12.Mul(f4, f3)

	// Hard part
	y0 := ExpByNegX(e12, r)
	y1 := e12.Square(y0)
	y2 := e12.Square(y1)
	y3 := e12.Mul(y2, y1)
	y4 := ExpByNegX(e12, y3)
	y5 := e12.Square(y4)
	y6 := ExpByNegX(e12, y5)
	y3_cyclo_inv := e12.Conjugate(y3)
	y6_cyclo_inv := e12.Conjugate(y6)
	y7 := e12.Mul(y6_cyclo_inv, y4)
	y8 := e12.Mul(y7, y3_cyclo_inv)
	y9 := e12.Mul(y8, y1)
	y10 := e12.Mul(y8, y4)
	y11 := e12.Mul(y10, r)
	y12 := Frobenius(e2, y9)
	y13 := e12.Mul(y12, y11)
	y8_frobenius := FrobeniusSquare(e2, y8)
	y14 := e12.Mul(y8_frobenius, y13)
	r_cyclo_inv := e12.Conjugate(r)
	y15 := e12.Mul(r_cyclo_inv, y9)
	y15_frobenius := FrobeniusCube(e2, y15)
	res := e12.Mul(y15_frobenius, y14)

	return res
}

// Ell computes the line evaluation in the pairing computation
func Ell(e2 *field_tower.Ext2, e6 *field_tower.Ext6, x *field_tower.Fp12, b *field_tower.Fp6, P *groups.G1Affine) *field_tower.Fp12 {

	// Compute c0
	c0 := e2.MulByElement(&b.A0, &P.Y)

	// Compute c1
	c1 := e2.MulByElement(&b.A1, &P.X)

	// Compute updated_f = MulBy034()(x, c0, c1, b.z)
	updated_f := MulBy034(e2, e6, x, c0, c1, &b.A2)

	return updated_f
}

// Computes the line coefficients and the resulting point when doubling a point on the G2 curve in projective coordinates.
func LineDouble(e *frontend.API, e2 *field_tower.Ext2, R *groups.G2Projective, twoInv frontend.Variable) (*groups.G2Projective, *field_tower.Fp6) {

	// Initialize output variables
	var R_Double groups.G2Projective
	var ell_coeff field_tower.Fp6

	// Compute intermediate values
	a_first1 := e2.Mul(&R.X, &R.Y)
	a := e2.MulByElement(a_first1, &twoInv)

	b := e2.Mul(&R.Y, &R.Y)
	c := e2.Mul(&R.Z, &R.Z)

	c_double := e2.Add(c, c)
	c2_plus_c := e2.Add(c_double, c)

	a0_temp, _ := new(big.Int).SetString("19485874751759354771024239261021720505790618469301721065564631296452457478373", 10)
	a0_tempVar := frontend.Variable(*a0_temp)

	a1_temp, _ := new(big.Int).SetString("266929791119991161246907387137283842545076965332900288569378510910307636690", 10)
	a1_tempVar := frontend.Variable(*a1_temp)

	// Define COEFF_B
	COEFF_B := field_tower.Fp2{
		A0: a0_tempVar,
		A1: a1_tempVar,
	}

	e_val := e2.Mul(&COEFF_B, c2_plus_c)
	e_double := e2.Add(e_val, e_val)
	f := e2.Add(e_double, e_val)

	g_part1 := e2.Add(b, f)
	g := e2.MulByElement(g_part1, &twoInv)

	h_part1 := e2.Add(&R.Y, &R.Z)
	h_part2 := e2.Mul(h_part1, h_part1)
	b_plus_c := e2.Add(b, c)
	h := e2.Sub(h_part2, b_plus_c)

	i := e2.Sub(e_val, b)
	j := e2.Mul(&R.X, &R.X)
	e_square := e2.Mul(e_val, e_val)
	b_minus_f := e2.Sub(b, f)
	R_Double.X = *e2.Mul(a, b_minus_f)

	g_square := e2.Mul(g, g)
	e_square_double := e2.Add(e_square, e_square)
	l := e2.Add(e_square_double, e_square)
	R_Double.Y = *e2.Sub(g_square, l)

	R_Double.Z = *e2.Mul(b, h)

	// Compute ell_coeff
	ell_coeff.A0.A0 = (*e).Neg(h.A0)
	ell_coeff.A0.A1 = (*e).Neg(h.A1)
	ell_coeff.A1 = *e2.Add(e2.Add(j, j), j)
	ell_coeff.A2 = *i

	return &R_Double, &ell_coeff
}

// Computes the line coefficients and the resulting point when adding a G2 projective point (R) and a G2 affine point (Q).
func LineAddition(e *frontend.API, e2 *field_tower.Ext2, R *groups.G2Projective, Q *groups.G2Affine) (*groups.G2Projective, *field_tower.Fp6) {

	// Initialize output variables
	var R_New groups.G2Projective
	var ell_coeff field_tower.Fp6

	// Compute intermediate values
	Qy_Rz := e2.Mul(&Q.Y, &R.Z)
	theta := e2.Sub(&R.Y, Qy_Rz)

	Qx_Rz := e2.Mul(&Q.X, &R.Z)
	lambda := e2.Sub(&R.X, Qx_Rz)

	c := e2.Mul(theta, theta)
	d := e2.Mul(lambda, lambda)
	e_val := e2.Mul(lambda, d)
	f := e2.Mul(&R.Z, c)
	g := e2.Mul(&R.X, d)
	g_double := e2.Add(g, g)

	h_temp := e2.Add(e_val, f)
	h := e2.Sub(h_temp, g_double)

	// Compute R_New.x
	R_New.X = *e2.Mul(lambda, h)

	// Compute R_New.y
	g_minus_h := e2.Sub(g, h)
	e_Ry := e2.Mul(e_val, &R.Y)
	theta_g_minus_h := e2.Mul(theta, g_minus_h)
	R_New.Y = *e2.Sub(theta_g_minus_h, e_Ry)
	// Compute R_New.z
	R_New.Z = *e2.Mul(&R.Z, e_val)

	// Compute ell_coeff
	theta_Qx := e2.Mul(theta, &Q.X)
	lambda_Qy := e2.Mul(lambda, &Q.Y)
	j := e2.Sub(theta_Qx, lambda_Qy)

	ell_coeff.A0 = *lambda
	ell_coeff.A1.A0 = (*e).Neg(theta.A0)
	ell_coeff.A1.A1 = (*e).Neg(theta.A1)
	ell_coeff.A2 = *j

	return &R_New, &ell_coeff
}

func (e PairingAPI) EllCoeffs(Q *groups.G2Affine) ([]field_tower.Fp6, []groups.G2Projective) {

	// Define constants
	n := 64
	twoInv := e.api.Inverse(frontend.Variable(2))

	// Initialize arrays for ell_coeff and R
	ell_coeff := make([]field_tower.Fp6, 2*n+2)
	R := make([]groups.G2Projective, 2*n+2)

	// Convert Q to projective coordinates
	R[0] = *e.g2_api.ToProjective(Q)

	// Compute neg_Q
	var neg_Q groups.G2Affine
	neg_Q.X = Q.X
	neg_Q.Y.A1 = e.api.Neg(Q.Y.A1)
	neg_Q.Y.A0 = e.api.Neg(Q.Y.A0)

	// Define bits array
	bits := []int{
		0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
		0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
		-1, 0, 0, 0, 1, 0, 1,
	}

	// Main loop
	for i := 0; i < n; i++ {
		// Perform LineDouble
		R_New, ell_coeff_New := LineDouble(&e.api, &e.e2, &R[2*i], twoInv)
		R[2*i+1] = *R_New
		ell_coeff[2*i] = *ell_coeff_New

		// Perform LineAddition based on bits
		if bits[n-i-1] == 1 {
			R_New, ell_coeff_New := LineAddition(&e.api, &e.e2, &R[2*i+1], Q)
			R[2*i+2] = *R_New
			ell_coeff[2*i+1] = *ell_coeff_New
		} else if bits[n-i-1] == -1 {
			R_New, ell_coeff_New := LineAddition(&e.api, &e.e2, &R[2*i+1], &neg_Q)
			R[2*i+2] = *R_New
			ell_coeff[2*i+1] = *ell_coeff_New
		} else {
			R[2*i+2] = R[2*i+1]
			ell_coeff[2*i+1] = ell_coeff[2*i]
		}
	}

	// Compute Q1 and Q2 using MulByChar
	Q1 := MulByChar(&e.e2, Q)
	Q2 := MulByChar(&e.e2, Q1)

	// Compute Q2_neg
	var Q2_neg groups.G2Affine
	Q2_neg.X = Q2.X
	Q2_neg.Y.A0 = e.api.Neg(Q2.Y.A0)
	Q2_neg.Y.A1 = e.api.Neg(Q2.Y.A1)

	// Final LineAddition operations
	R_New, ell_coeff_New := LineAddition(&e.api, &e.e2, &R[2*n], Q1)
	R[2*n+1] = *R_New
	ell_coeff[2*n] = *ell_coeff_New
	_, ell_coeffs := LineAddition(&e.api, &e.e2, &R[2*n+1], &Q2_neg)
	ell_coeff[2*n+1] = *ell_coeffs

	return ell_coeff, R
}

func MulByChar(e2 *field_tower.Ext2, Q *groups.G2Affine) *groups.G2Affine {

	TWIST_MUL_BY_Q_X_A0, _ := new(big.Int).SetString("21575463638280843010398324269430826099269044274347216827212613867836435027261", 10)
	TWIST_MUL_BY_Q_X_A0Var := frontend.Variable(*TWIST_MUL_BY_Q_X_A0)

	TWIST_MUL_BY_Q_X_A1, _ := new(big.Int).SetString("10307601595873709700152284273816112264069230130616436755625194854815875713954", 10)
	TWIST_MUL_BY_Q_X_A1Var := frontend.Variable(*TWIST_MUL_BY_Q_X_A1)

	TWIST_MUL_BY_Q_Y_A0, _ := new(big.Int).SetString("2821565182194536844548159561693502659359617185244120367078079554186484126554", 10)
	TWIST_MUL_BY_Q_Y_A0Var := frontend.Variable(*TWIST_MUL_BY_Q_Y_A0)

	TWIST_MUL_BY_Q_Y_A1, _ := new(big.Int).SetString("3505843767911556378687030309984248845540243509899259641013678093033130930403", 10)
	TWIST_MUL_BY_Q_Y_A1Var := frontend.Variable(*TWIST_MUL_BY_Q_Y_A1)

	// Define constants TWIST_MUL_BY_Q_X and TWIST_MUL_BY_Q_Y
	TWIST_MUL_BY_Q_X := field_tower.Fp2{
		A0: TWIST_MUL_BY_Q_X_A0Var,
		A1: TWIST_MUL_BY_Q_X_A1Var,
	}

	TWIST_MUL_BY_Q_Y := field_tower.Fp2{
		A0: TWIST_MUL_BY_Q_Y_A0Var,
		A1: TWIST_MUL_BY_Q_Y_A1Var,
	}

	// Compute Frobenius of Q.x and Q.y
	t1 := e2.Conjugate(&Q.X)
	t2 := e2.Conjugate(&Q.Y)

	// Compute res.x and res.y
	outX := e2.Mul(t1, &TWIST_MUL_BY_Q_X)
	outY := e2.Mul(t2, &TWIST_MUL_BY_Q_Y)

	// Construct the output groups.G2Affine element
	res := &groups.G2Affine{
		X: *outX,
		Y: *outY,
	}

	return res
}

func (e PairingAPI) MillerLoop(Q *groups.G2Affine, P *groups.G1Projective) *field_tower.Fp12 {

	// Define constants
	n := 64
	bits := []int{
		0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
		0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
		-1, 0, 0, 0, 1, 0, 1,
	}

	// Convert P to affine coordinates

	p := e.g1_api.ToAffine(P)

	// Compute ell_coeff using EllCoeffs
	ell_coeff, _ := e.EllCoeffs(Q)

	// Initialize Fp12 array
	f := make([]field_tower.Fp12, 3*n+3)
	f[0] = *e.e12.One()

	// Main loop
	for i := 0; i < n; i++ {
		// Square f[3*i]
		f[3*i+1] = *e.e12.Mul(&f[3*i], &f[3*i])

		// Apply Ell with ell_coeff[2*i]
		f[3*i+2] = *Ell(&e.e2, &e.e6, &f[3*i+1], &ell_coeff[2*i], p)

		// Apply Ell or propagate based on bits
		if bits[n-i-1] == 1 {
			f[3*i+3] = *Ell(&e.e2, &e.e6, &f[3*i+2], &ell_coeff[2*i+1], p)
		} else if bits[n-i-1] == -1 {
			f[3*i+3] = *Ell(&e.e2, &e.e6, &f[3*i+2], &ell_coeff[2*i+1], p)
		} else {
			f[3*i+3] = f[3*i+2]
		}
	}

	// Final Ell applications
	f[3*n+1] = *Ell(&e.e2, &e.e6, &f[3*n], &ell_coeff[2*n], p)
	f[3*n+2] = *Ell(&e.e2, &e.e6, &f[3*n+1], &ell_coeff[2*n+1], p)

	// Output the result
	return &f[3*n+2]
}

type PairingAPI struct {
	e2     field_tower.Ext2
	e6     field_tower.Ext6
	e12    field_tower.Ext12
	g1_api groups.G1API
	g2_api groups.G2API
	api    frontend.API
}

func New(api frontend.API) *PairingAPI {
	return &PairingAPI{
		e2:     *field_tower.New(api),
		e6:     *field_tower.NewExt6(api),
		e12:    *field_tower.NewExt12(api),
		g1_api: *groups.NewG1API(api),
		g2_api: *groups.New(api),
		api:    api,
	}
}

func (e PairingAPI) Pairing(Q *groups.G2Affine, P *groups.G1Projective) *field_tower.Fp12 {

	miller_output := e.MillerLoop(Q, P)
	res := FinalExp(&e.e2, &e.e12, miller_output)
	return res
}

func (e PairingAPI) MillerLoopStepIntegrated(
	Rin *groups.G2Projective, // R[2*i]
	// Q, negQ *groups.G2Affine, // Q and -Q
	Q *groups.G2Affine, // Q
	p *groups.G1Affine, // affine P
	fIn *field_tower.Fp12, // f[3*i]
	bit frontend.Variable, // {-1, 0, 1}
	twoInv frontend.Variable,
) (Rout groups.G2Projective, f1, f2, f3 field_tower.Fp12) {

	// compute negQ
	var negQ groups.G2Affine
	negQ.X = Q.X
	negQ.Y.A0 = e.api.Neg(Q.Y.A0)
	negQ.Y.A1 = e.api.Neg(Q.Y.A1)

	// Step 1: LineDouble
	RmidPtr, ell1Ptr := LineDouble(&e.api, &e.e2, Rin, twoInv)
	Rmid := *RmidPtr
	ell1 := *ell1Ptr

	// Compute selectors for bit == 1, bit == -1
	isOne := e.api.IsZero(e.api.Sub(bit, frontend.Variable(1)))      // bit == 1
	isMinusOne := e.api.IsZero(e.api.Add(bit, frontend.Variable(1))) // bit == -1

	// Line additions
	Rout1Ptr, ell2_1Ptr := LineAddition(&e.api, &e.e2, &Rmid, Q)
	RoutMinus1Ptr, ell2_minus1Ptr := LineAddition(&e.api, &e.e2, &Rmid, &negQ)

	// Select Rout.X
	RoutX := e.e2.Select(isOne, &Rout1Ptr.X, &Rmid.X)
	RoutX = e.e2.Select(isMinusOne, &RoutMinus1Ptr.X, RoutX)
	// Select Rout.Y
	RoutY := e.e2.Select(isOne, &Rout1Ptr.Y, &Rmid.Y)
	RoutY = e.e2.Select(isMinusOne, &RoutMinus1Ptr.Y, RoutY)
	// Select Rout.Z
	RoutZ := e.e2.Select(isOne, &Rout1Ptr.Z, &Rmid.Z)
	RoutZ = e.e2.Select(isMinusOne, &RoutMinus1Ptr.Z, RoutZ)

	Rout = groups.G2Projective{
		X: *RoutX,
		Y: *RoutY,
		Z: *RoutZ,
	}

	// Select ell2
	ell2 := *e.e6.Select(isOne, ell2_1Ptr, &ell1)
	ell2 = *e.e6.Select(isMinusOne, ell2_minus1Ptr, &ell2)

	// Miller loop evaluation
	f1 = *e.e12.Mul(fIn, fIn)                   // f1 = fIn^2
	f2 = *Ell(&e.e2, &e.e6, &f1, &ell1, p)      // f2 = Ell(f1, ell1)
	f3_val := *Ell(&e.e2, &e.e6, &f2, &ell2, p) // f3_val = Ell(f2, ell2)

	// Conditionally select f3
	isZero := e.api.IsZero(bit)
	f3 = *e.e12.Select(isZero, &f2, &f3_val)

	return
}

func (e PairingAPI) FinalMillerLoopStepIntegrated(
	Rin *groups.G2Projective, // R[2n]
	Q *groups.G2Affine, // Q
	p *groups.G1Affine, // affine P
	fIn *field_tower.Fp12, // f[3n]
) (Rout groups.G2Projective, f2 field_tower.Fp12) {
	// Step 1: Frobenius twists
	Q1 := MulByChar(&e.e2, Q)
	Q2 := MulByChar(&e.e2, Q1)

	// Step 2: Compute -Q2
	var Q2Neg groups.G2Affine
	Q2Neg.X = Q2.X
	Q2Neg.Y.A0 = e.api.Neg(Q2.Y.A0)
	Q2Neg.Y.A1 = e.api.Neg(Q2.Y.A1)

	// Step 3: Line addition with Q1
	R1Ptr, ell1 := LineAddition(&e.api, &e.e2, Rin, Q1)
	R1 := *R1Ptr

	// Step 4: Line addition with -Q2
	R2Ptr, ell2 := LineAddition(&e.api, &e.e2, &R1, &Q2Neg)
	Rout = *R2Ptr

	// Step 5: Ell evaluations
	f1 := *Ell(&e.e2, &e.e6, fIn, ell1, p) // f1 = Ell(fIn, ell1)
	f2 = *Ell(&e.e2, &e.e6, &f1, ell2, p)  // f2 = Ell(f1, ell2)

	return
}

// Pairing Step Circuit: Miller loop step
type MillerStepCircuit struct {
	FIn  field_tower.Fp12 `gnark:",public"`
	P    groups.G1Affine  `gnark:",public"`
	Q    groups.G2Affine  `gnark:",public"`
	Rin  groups.G2Projective
	Rout groups.G2Projective
	Bit  frontend.Variable
	FOut [3]field_tower.Fp12

	// Native values (internal use)
	fIn  bn254.E12
	p    bn254.G1Affine
	q    bn254.G2Affine
	rin  G2Projective
	rout G2Projective
	bit  int
	fOut [3]bn254.E12
}

func (step_circuit *MillerStepCircuit) Define(api frontend.API) error {
	pairing := New(api)
	twoInv := api.Inverse(frontend.Variable(2))

	_, f1, f2, f3 := pairing.MillerLoopStepIntegrated(
		&step_circuit.Rin, &step_circuit.Q, &step_circuit.P, &step_circuit.FIn, step_circuit.Bit, twoInv,
	)
	e12 := field_tower.NewExt12(api)
	e12.AssertIsEqual(&f1, &step_circuit.FOut[0])
	e12.AssertIsEqual(&f2, &step_circuit.FOut[1])
	e12.AssertIsEqual(&f3, &step_circuit.FOut[2])
	return nil
}

func (step_circuit *MillerStepCircuit) Hint() {
	step_circuit.rout, step_circuit.fOut[0], step_circuit.fOut[1], step_circuit.fOut[2] = MillerLoopStepIntegrated_fn(
		&step_circuit.rin, &step_circuit.q, &step_circuit.p, &step_circuit.fIn, step_circuit.bit)
}

func (step_circuit *MillerStepCircuit) GenerateWitness(constraints constraint.ConstraintSystem) grumpkin_fr.Vector {
	w, err := frontend.NewWitness(step_circuit, ecc.GRUMPKIN.ScalarField())

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

// Miller Uniform Circuit: Chains 64 steps
type MillerUniformCircuit struct {
	P   groups.G1Affine  `gnark:",public"`
	Q   groups.G2Affine  `gnark:",public"`
	FIn field_tower.Fp12 `gnark:",public"`

	FOut                field_tower.Fp12
	Miller_step_circuit *MillerStepCircuit

	// Native
	p    bn254.G1Affine
	q    bn254.G2Affine
	fOut bn254.E12
}

func (miller_uniform_circuit *MillerUniformCircuit) CreateStepCircuit() constraint.ConstraintSystem {
	miller_uniform_circuit.Miller_step_circuit = &MillerStepCircuit{
		p: miller_uniform_circuit.p,
		q: miller_uniform_circuit.q,
	}
	constraints, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, miller_uniform_circuit.Miller_step_circuit)
	return constraints
}

func (miller_uniform_circuit *MillerUniformCircuit) GenerateWitness(constraints constraint.ConstraintSystem) grumpkin_fr.Vector {
	// Constants
	n := 64
	bits := []int{
		0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
		0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
		-1, 0, 0, 0, 1, 0, 1,
	}

	var FIn bn254.E12
	FIn.SetOne()

	rIn := ToProjective_fn(&miller_uniform_circuit.q)

	var witness grumpkin_fr.Vector
	for i := 0; i < n; i++ {
		bit := bits[n-1-i]
		miller_uniform_circuit.Miller_step_circuit.rin = rIn
		miller_uniform_circuit.Miller_step_circuit.Rin = G2ProjectiveFromBNG2Projective(&miller_uniform_circuit.Miller_step_circuit.rin)

		miller_uniform_circuit.Miller_step_circuit.FIn = field_tower.FromE12(&FIn)
		miller_uniform_circuit.Miller_step_circuit.fIn = FIn

		miller_uniform_circuit.Miller_step_circuit.P = groups.AffineFromG1Affine(&miller_uniform_circuit.p)
		miller_uniform_circuit.Miller_step_circuit.Q = groups.G2AffineFromBNG2Affine(&miller_uniform_circuit.q)

		miller_uniform_circuit.Miller_step_circuit.Bit = bit
		miller_uniform_circuit.Miller_step_circuit.bit = bit

		miller_uniform_circuit.Miller_step_circuit.Hint()

		// FIn for next step
		FIn = miller_uniform_circuit.Miller_step_circuit.fOut[2]

		miller_uniform_circuit.Miller_step_circuit.Rout = G2ProjectiveFromBNG2Projective(&miller_uniform_circuit.Miller_step_circuit.rout)
		miller_uniform_circuit.Miller_step_circuit.FOut[0] = field_tower.FromE12(&miller_uniform_circuit.Miller_step_circuit.fOut[0])
		miller_uniform_circuit.Miller_step_circuit.FOut[1] = field_tower.FromE12(&miller_uniform_circuit.Miller_step_circuit.fOut[1])
		miller_uniform_circuit.Miller_step_circuit.FOut[2] = field_tower.FromE12(&miller_uniform_circuit.Miller_step_circuit.fOut[2])

		// RIn for next step
		rIn = miller_uniform_circuit.Miller_step_circuit.rout

		stepWitness := miller_uniform_circuit.Miller_step_circuit.GenerateWitness(constraints)
		witness = append(witness, stepWitness...)

	}
	miller_uniform_circuit.fOut = FIn
	miller_uniform_circuit.FOut = field_tower.FromE12(&miller_uniform_circuit.fOut)

	return witness
}

type MillerEllFinalStepCircuit struct {
	FIn  field_tower.Fp12 `gnark:",public"`
	P    groups.G1Affine  `gnark:",public"`
	Q    groups.G2Affine  `gnark:",public"`
	Rin  groups.G2Projective
	Rout groups.G2Projective
	FOut field_tower.Fp12 `gnark:",public"`

	// Native
	fIn  bn254.E12
	fOut bn254.E12
	p    bn254.G1Affine
	q    bn254.G2Affine
	rin  G2Projective
	rout G2Projective
}

func (c *MillerEllFinalStepCircuit) Define(api frontend.API) error {
	p := New(api)
	rOut, fOut := p.FinalMillerLoopStepIntegrated(&c.Rin, &c.Q, &c.P, &c.FIn)

	p.e2.AssertIsEqual(&rOut.X, &c.Rout.X)
	p.e2.AssertIsEqual(&rOut.Y, &c.Rout.Y)
	p.e2.AssertIsEqual(&rOut.Z, &c.Rout.Z)
	p.e12.AssertIsEqual(&fOut, &c.FOut)
	return nil
}

func (circuit *MillerEllFinalStepCircuit) Hint() {
	circuit.rout, circuit.fOut = FinalMillerLoopStepIntegrated_fn(&circuit.rin, &circuit.q, &circuit.p, &circuit.fIn)
}

func (circuit *MillerEllFinalStepCircuit) Compile() constraint.ConstraintSystem {
	circuitR1CS, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("err in compilation is ", err)
	}
	return circuitR1CS
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

type PairingUniformCircuit struct {
	P   groups.G1Affine  `gnark:",public"`
	Q   groups.G2Affine  `gnark:",public"`
	Res field_tower.Fp12 `gnark:",public"`

	// Native
	p   bn254.G1Affine
	q   bn254.G2Affine
	res bn254.E12

	Miller_uniform *MillerUniformCircuit
	Miller_final   *MillerEllFinalStepCircuit
}

func (p *PairingUniformCircuit) CreateStepCircuits() []constraint.ConstraintSystem {
	p.Miller_uniform.P = p.P
	p.Miller_uniform.Q = p.Q
	p.Miller_uniform.p = p.p
	p.Miller_uniform.q = p.q

	cs1 := p.Miller_uniform.CreateStepCircuit()
	cs2 := p.Miller_final.Compile()
	return []constraint.ConstraintSystem{cs1, cs2}
}

func (p *PairingUniformCircuit) GenerateWitness(constraints []constraint.ConstraintSystem) grumpkin_fr.Vector {
	var witness grumpkin_fr.Vector

	// Generate witness for Miller loop (64 steps)
	witnessMiller := p.Miller_uniform.GenerateWitness(constraints[0])
	witness = append(witness, witnessMiller...)

	// ========== Final Ell Step ==========
	p.Miller_final.fIn = p.Miller_uniform.fOut
	p.Miller_final.rin = p.Miller_uniform.Miller_step_circuit.rout
	p.Miller_final.q = p.q
	p.Miller_final.p = p.p

	// Hint to compute output
	p.Miller_final.Hint()

	// Assign for constraints
	p.Miller_final.FIn = field_tower.FromE12(&p.Miller_uniform.fOut)
	p.Miller_final.Rin = p.Miller_uniform.Miller_step_circuit.Rout
	p.Miller_final.P = p.Miller_uniform.P
	p.Miller_final.Q = p.Miller_uniform.Q
	p.Miller_final.FOut = field_tower.FromE12(&p.Miller_final.fOut)
	p.Miller_final.Rout = G2ProjectiveFromBNG2Projective(&p.Miller_final.rout)

	// Solve final circuit and extract witness
	w, err := frontend.NewWitness(p.Miller_final, ecc.GRUMPKIN.ScalarField())
	if err != nil {
		fmt.Println("final step witness error:", err)
	}
	wSolved, _ := constraints[1].Solve(w)
	wStep := wSolved.(*cs.R1CSSolution).W

	for _, elem := range wStep {
		witness = append(witness, grumpkin_fr.Element(elem))
	}

	p.res = p.Miller_final.fOut
	p.Res = field_tower.FromE12(&p.res)

	return witness
}
