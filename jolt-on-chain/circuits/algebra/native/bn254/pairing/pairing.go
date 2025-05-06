package pairing

import (
	"math/big"

	"github.com/arithmic/gnark/frontend"
	field_tower "github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/field_tower"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

func ExpByNegX(e *frontend.API, x *field_tower.Fp12) *field_tower.Fp12 {

	e12 := field_tower.NewExt12(*e)

	XVar := frontend.Variable(4965661367192848881)
	t := e12.Exp(x, &XVar)

	out := e12.Conjugate(t)

	return out

}

func Gamma1(e *frontend.API) [6]field_tower.Fp2 {
	e2 := field_tower.NewExt2(*e)
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
	gamma1[0] = field_tower.Fp2{
		A0: frontend.Variable(1),
		A1: frontend.Variable(0),
	}
	// Compute gamma1[i] = gamma1[i-1] * shi_c for i = 1 to 5
	for i := 1; i <= 5; i++ {
		gamma1[i] = *e2.Mul(&gamma1[i-1], shiC)
	}

	return gamma1
}

func Gamma2(e *frontend.API, gamma1 [6]field_tower.Fp2) [6]field_tower.Fp2 {
	var gamma2 [6]field_tower.Fp2

	e2 := field_tower.NewExt2(*e)

	// Compute gamma2[i] = gamma1[i] * Fp2conjugate()(gamma1[i]) for i = 1 to 5
	for i := 1; i <= 5; i++ {
		// Compute the conjugate of gamma1[i]
		gamma1Conjugate := e2.Conjugate(&gamma1[i])

		// Multiply gamma1[i] with its conjugate
		gamma2[i] = *e2.Mul(&gamma1[i], gamma1Conjugate)
	}

	return gamma2
}

func Gamma3(e *frontend.API, gamma1 [6]field_tower.Fp2, gamma2 [6]field_tower.Fp2) [6]field_tower.Fp2 {
	var gamma3 [6]field_tower.Fp2

	e2 := field_tower.NewExt2(*e)

	// Compute gamma3[i] = gamma1[i] * gamma2[i] for i = 1 to 5
	for i := 1; i <= 5; i++ {
		gamma3[i] = *e2.Mul(&gamma1[i], &gamma2[i])
	}

	return gamma3
}

// Computes Frobenius(x)
func Frobenius(e *frontend.API, op1 *field_tower.Fp12) *field_tower.Fp12 {
	e2 := field_tower.NewExt2(*e)

	var t [7]field_tower.Fp2
	var u [7]field_tower.Fp2

	// Compute conjugates of op1 components
	t[1] = *e2.Conjugate(&op1.A0.A0)
	t[2] = *e2.Conjugate(&op1.A1.A0)
	t[3] = *e2.Conjugate(&op1.A0.A1)
	t[4] = *e2.Conjugate(&op1.A1.A1)
	t[5] = *e2.Conjugate(&op1.A0.A2)
	t[6] = *e2.Conjugate(&op1.A1.A2)

	// Compute gamma1
	gamma1 := Gamma1(e)

	// Compute u[i] = t[i] * gamma1[i-1] for i = 2 to 6
	for i := 2; i <= 6; i++ {
		u[i] = *e2.Mul(&t[i], &gamma1[i-1])
	}

	// Construct c0 and c1
	c0 := field_tower.Fp6{
		A0: t[1],
		A1: u[3],
		A2: u[5],
	}
	c1 := field_tower.Fp6{
		A0: u[2],
		A1: u[4],
		A2: u[6],
	}

	// Construct the output Fp12 element
	out := field_tower.Fp12{
		A0: c0,
		A1: c1,
	}

	return &out

}

// Computes Frobenius^2(x)
func FrobeniusSquare(e *frontend.API, op1 *field_tower.Fp12) *field_tower.Fp12 {
	e2 := field_tower.NewExt2(*e)

	// Compute gamma1
	gamma1 := Gamma1(e)

	// Compute gamma2 using gamma1
	gamma2 := Gamma2(e, gamma1)

	// Compute intermediate values u2, u3, u4, u5, u6
	u2 := *e2.Mul(&op1.A1.A0, &gamma2[1])
	u3 := *e2.Mul(&op1.A0.A1, &gamma2[2])
	u4 := *e2.Mul(&op1.A1.A1, &gamma2[3])
	u5 := *e2.Mul(&op1.A0.A2, &gamma2[4])
	u6 := *e2.Mul(&op1.A1.A2, &gamma2[5])

	// Construct c0 and c1
	c0 := field_tower.Fp6{
		A0: op1.A0.A0,
		A1: u3,
		A2: u5,
	}
	c1 := field_tower.Fp6{
		A0: u2,
		A1: u4,
		A2: u6,
	}

	// Construct the output Fp12 element
	out := field_tower.Fp12{
		A0: c0,
		A1: c1,
	}

	return &out
}

// Computes Frobenius^3(x)
func FrobeniusCube(e *frontend.API, op1 *field_tower.Fp12) *field_tower.Fp12 {
	e2 := field_tower.NewExt2(*e)

	var t [7]field_tower.Fp2
	var u [7]field_tower.Fp2

	// Compute conjugates of op1 components
	t[1] = *e2.Conjugate(&op1.A0.A0)
	t[2] = *e2.Conjugate(&op1.A1.A0)
	t[3] = *e2.Conjugate(&op1.A0.A1)
	t[4] = *e2.Conjugate(&op1.A1.A1)
	t[5] = *e2.Conjugate(&op1.A0.A2)
	t[6] = *e2.Conjugate(&op1.A1.A2)

	// Compute gamma1
	gamma1 := Gamma1(e)

	// Compute gamma2 using gamma1
	gamma2 := Gamma2(e, gamma1)

	// Compute gamma3 using gamma1 and gamma2
	gamma3 := Gamma3(e, gamma1, gamma2)

	// Compute u[i] = t[i] * gamma3[i-1] for i = 2 to 6
	for i := 2; i <= 6; i++ {
		u[i] = *e2.Mul(&t[i], &gamma3[i-1])
	}

	// Construct c0 and c1
	c0 := field_tower.Fp6{
		A0: t[1],
		A1: u[3],
		A2: u[5],
	}
	c1 := field_tower.Fp6{
		A0: u[2],
		A1: u[4],
		A2: u[6],
	}

	// Construct the output Fp12 element
	out := field_tower.Fp12{
		A0: c0,
		A1: c1,
	}

	return &out
}

// Computes the multiplication of an Fp12 element by a sparse element of the form (c0, 0, 0, c3, c4, 0).
// This optimization leverages the sparsity of the multiplier to reduce the number of operations required.
func MulBy034(e *frontend.API, f *field_tower.Fp12, c0, c3, c4 *field_tower.Fp2) *field_tower.Fp12 {
	e6 := field_tower.NewExt6(*e)
	e2 := field_tower.NewExt2(*e)

	// Compute a.x, a.y, a.z
	a := field_tower.Fp6{
		A1: *e2.Mul(&f.A0.A1, c0),
		A0: *e2.Mul(&f.A0.A0, c0),
		A2: *e2.Mul(&f.A0.A2, c0),
	}

	b := MulBy01(e, &f.A1, c3, c4)

	c0_new := e2.Add(c0, c3)

	temp_e := e6.Add(&f.A0, &f.A1)

	e_result := MulBy01(e, temp_e, c0_new, c4)

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
func MulBy01(e *frontend.API, op1 *field_tower.Fp6, c0, c1 *field_tower.Fp2) *field_tower.Fp6 {
	e2 := field_tower.NewExt2(*e)

	a_a := e2.Mul(&op1.A0, c0)

	b_b := e2.Mul(&op1.A1, c1)

	// Compute t1
	tmp1 := e2.Add(&op1.A1, &op1.A2)
	tmp2 := e2.Mul(tmp1, c1)
	tmp3 := e2.Sub(tmp2, b_b)
	tmp4 := e2.MulByNonResidue(tmp3)
	t1 := e2.Add(tmp4, a_a)

	// Compute t3
	tmp5 := e2.Add(&op1.A0, &op1.A2)
	tmp6 := e2.Mul(tmp5, c0)
	tmp7 := e2.Sub(tmp6, a_a)
	t3 := e2.Add(tmp7, b_b)

	// Compute t2
	tmp8 := e2.Add(c0, c1)
	tmp9 := e2.Add(&op1.A0, &op1.A1)
	tmp10 := e2.Mul(tmp8, tmp9)
	tmp11 := e2.Sub(tmp10, a_a)
	t2 := e2.Sub(tmp11, b_b)

	// Construct the output Fp6 element
	out := field_tower.Fp6{
		A0: *t1,
		A1: *t2,
		A2: *t3,
	}

	return &out
}

// FinalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ
// where d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// we use instead d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// where s is the cofactor 2x₀(6x₀²+3x₀+1)
func FinalExp(e *frontend.API, f *field_tower.Fp12) *field_tower.Fp12 {
	e12 := field_tower.NewExt12(*e)

	// Easy part
	f1 := e12.Conjugate(f)
	f2 := e12.Inverse(f)
	f3 := e12.Mul(f1, f2)
	f4 := FrobeniusSquare(e, f3)
	r := e12.Mul(f4, f3)

	// Hard part
	y0 := ExpByNegX(e, r)
	y1 := e12.Square(y0)
	y2 := e12.Square(y1)
	y3 := e12.Mul(y2, y1)
	y4 := ExpByNegX(e, y3)
	y5 := e12.Square(y4)
	y6 := ExpByNegX(e, y5)
	y3_cyclo_inv := e12.Conjugate(y3)
	y6_cyclo_inv := e12.Conjugate(y6)
	y7 := e12.Mul(y6_cyclo_inv, y4)
	y8 := e12.Mul(y7, y3_cyclo_inv)
	y9 := e12.Mul(y8, y1)
	y10 := e12.Mul(y8, y4)
	y11 := e12.Mul(y10, r)
	y12 := Frobenius(e, y9)
	y13 := e12.Mul(y12, y11)
	y8_frobenius := FrobeniusSquare(e, y8)
	y14 := e12.Mul(y8_frobenius, y13)
	r_cyclo_inv := e12.Conjugate(r)
	y15 := e12.Mul(r_cyclo_inv, y9)
	y15_frobenius := FrobeniusCube(e, y15)
	out := e12.Mul(y15_frobenius, y14)

	return out
}

// ///////////////////////////////////////
// ToDo : Remove these and call these from groups
type G1Projective struct {
	X, Y, Z frontend.Variable
}

type G1Affine struct {
	X, Y frontend.Variable
}

type G2Projective struct {
	X, Y, Z field_tower.Fp2
}

type G2Affine struct {
	X, Y field_tower.Fp2
}
type G2 struct {
	e2 field_tower.Ext2
}

type G1 struct {
	api frontend.API
}

func NewG2(api frontend.API) *G2 {
	return &G2{e2: *field_tower.NewExt2(api)}
}

func (g G1) ToAffine(A *G1Projective) *G1Affine {
	return &G1Affine{
		X: g.api.Div(A.X, A.Z),
		Y: g.api.Div(A.Y, A.Z),
	}
}

// G2toProjective converts an affine G2 point into projective coordinates.
func (g2 *G2) G2toProjective(affine *G2Affine) *G2Projective {
	var one field_tower.Fp2
	var out G2Projective

	one.A0 = frontend.Variable(1)
	one.A1 = frontend.Variable(0)

	out.X = affine.X
	out.Y = affine.Y
	out.Z = one

	return &out
}

func G2AffineFromBNG2Affine(y *bn254.G2Affine) G2Affine {

	return G2Affine{
		X: field_tower.FromE2(&y.X),
		Y: field_tower.FromE2(&y.Y),
	}
}

func FromG1Affine(p *bn254.G1Affine) G1Projective {
	return G1Projective{
		X: grumpkin_fr.Element(p.X),
		Y: grumpkin_fr.Element(p.Y),
		Z: grumpkin_fr.One(),
	}
}

////////////////////////////////////////////////////////////////

// Ell computes the line evaluation in the pairing computation
func Ell(e *frontend.API, f *field_tower.Fp12, coeff *field_tower.Fp6, p *G1Affine) *field_tower.Fp12 {
	e2 := field_tower.NewExt2(*e)

	// Compute c0
	c0 := e2.MulByElement(&coeff.A0, &p.Y)

	// Compute c1
	c1 := e2.MulByElement(&coeff.A1, &p.X)

	// Compute updated_f = MulBy034()(f, c0, c1, coeff.z)
	updated_f := MulBy034(e, f, c0, c1, &coeff.A2)

	return updated_f
}

// Computes the line coefficients and the resulting point when doubling a point on the G2 curve in projective coordinates.
func LineDouble(e *frontend.API, R *G2Projective, twoInv frontend.Variable) (*G2Projective, *field_tower.Fp6) {
	e2 := field_tower.NewExt2(*e)

	// Initialize output variables
	var R_Double G2Projective
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

func LineAddition(e *frontend.API, R *G2Projective, Q *G2Affine) (*G2Projective, *field_tower.Fp6) {
	e2 := field_tower.NewExt2(*e)

	// Initialize output variables
	var R_New G2Projective
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

func EllCoeffs(e *frontend.API, Q *G2Affine) ([]field_tower.Fp6, []G2Projective) {

	// Define constants
	n := 64
	twoInv := (*e).Inverse(frontend.Variable(2))

	// Initialize arrays for ell_coeff and R
	ell_coeff := make([]field_tower.Fp6, 2*n+2)
	R := make([]G2Projective, 2*n+2)

	g2_api := NewG2(*e)
	// Convert Q to projective coordinates
	R[0] = *g2_api.G2toProjective(Q)

	// Compute neg_Q
	var neg_Q G2Affine
	neg_Q.X = Q.X
	neg_Q.Y.A1 = (*e).Neg(Q.Y.A1)
	neg_Q.Y.A0 = (*e).Neg(Q.Y.A0)

	// Define bits array
	bits := []int{
		0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
		0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
		-1, 0, 0, 0, 1, 0, 1,
	}

	// Main loop
	for i := 0; i < n; i++ {
		// Perform LineDouble
		R_New, ell_coeff_New := LineDouble(e, &R[2*i], twoInv)
		R[2*i+1] = *R_New
		ell_coeff[2*i] = *ell_coeff_New

		// Perform LineAddition based on bits
		if bits[n-i-1] == 1 {
			R_New, ell_coeff_New := LineAddition(e, &R[2*i+1], Q)
			R[2*i+2] = *R_New
			ell_coeff[2*i+1] = *ell_coeff_New
		} else if bits[n-i-1] == -1 {
			R_New, ell_coeff_New := LineAddition(e, &R[2*i+1], &neg_Q)
			R[2*i+2] = *R_New
			ell_coeff[2*i+1] = *ell_coeff_New
		} else {
			R[2*i+2] = R[2*i+1]
			ell_coeff[2*i+1] = ell_coeff[2*i]
		}
	}

	// Compute Q1 and Q2 using MulByChar
	Q1 := MulByChar(e, Q)
	Q2 := MulByChar(e, Q1)

	// Compute Q2_neg
	var Q2_neg G2Affine
	Q2_neg.X = Q2.X
	Q2_neg.Y.A0 = (*e).Neg(Q2.Y.A0)
	Q2_neg.Y.A1 = (*e).Neg(Q2.Y.A1)

	// Final LineAddition operations
	R_New, ell_coeff_New := LineAddition(e, &R[2*n], Q1)
	R[2*n+1] = *R_New
	ell_coeff[2*n] = *ell_coeff_New
	_, ell_coeffs := LineAddition(e, &R[2*n+1], &Q2_neg)
	ell_coeff[2*n+1] = *ell_coeffs

	return ell_coeff, R
}

func MulByChar(e *frontend.API, in *G2Affine) *G2Affine {
	e2 := field_tower.NewExt2(*e)

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

	// Compute Frobenius of in.x and in.y
	t1 := e2.Conjugate(&in.X)
	t2 := e2.Conjugate(&in.Y)

	// Compute out.x and out.y
	outX := e2.Mul(t1, &TWIST_MUL_BY_Q_X)
	outY := e2.Mul(t2, &TWIST_MUL_BY_Q_Y)

	// Construct the output G2Affine element
	out := &G2Affine{
		X: *outX,
		Y: *outY,
	}

	return out
}

func MillerLoop(e *frontend.API, Q *G2Affine, P *G1Projective) *field_tower.Fp12 {
	e12 := field_tower.NewExt12(*e)

	// Define constants
	n := 64
	bits := []int{
		0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
		0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
		-1, 0, 0, 0, 1, 0, 1,
	}

	// Convert P to affine coordinates
	g1 := G1{api: *e}
	p := g1.ToAffine(P)

	// Compute ell_coeff using EllCoeffs
	ell_coeff, _ := EllCoeffs(e, Q)

	// Initialize Fp2 and Fp6 constants
	zero_2 := field_tower.Fp2{A0: frontend.Variable(0), A1: frontend.Variable(0)}
	one_2 := field_tower.Fp2{A0: frontend.Variable(1), A1: frontend.Variable(0)}

	zero_6 := field_tower.Fp6{A0: zero_2, A1: zero_2, A2: zero_2}
	one_6 := field_tower.Fp6{A0: one_2, A1: zero_2, A2: zero_2}

	// Initialize Fp12 array
	f := make([]field_tower.Fp12, 3*n+3)
	f[0] = field_tower.Fp12{A0: one_6, A1: zero_6}

	// Main loop
	for i := 0; i < n; i++ {
		// Square f[3*i]
		f[3*i+1] = *e12.Mul(&f[3*i], &f[3*i])

		// Apply Ell with ell_coeff[2*i]
		f[3*i+2] = *Ell(e, &f[3*i+1], &ell_coeff[2*i], p)

		// Apply Ell or propagate based on bits
		if bits[n-i-1] == 1 {
			f[3*i+3] = *Ell(e, &f[3*i+2], &ell_coeff[2*i+1], p)
		} else if bits[n-i-1] == -1 {
			f[3*i+3] = *Ell(e, &f[3*i+2], &ell_coeff[2*i+1], p)
		} else {
			f[3*i+3] = f[3*i+2]
		}
	}

	// Final Ell applications
	f[3*n+1] = *Ell(e, &f[3*n], &ell_coeff[2*n], p)
	f[3*n+2] = *Ell(e, &f[3*n+1], &ell_coeff[2*n+1], p)

	// Output the result
	return &f[3*n+2]
}

func Pairing(e *frontend.API, Q *G2Affine, P *G1Projective) *field_tower.Fp12 {

	miller_output := MillerLoop(e, Q, P)

	out := FinalExp(e, miller_output)
	return out
}
