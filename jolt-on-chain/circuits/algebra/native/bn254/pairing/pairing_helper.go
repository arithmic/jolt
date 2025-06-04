package pairing

import (
	field_tower "github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/field_tower"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/groups"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

func Ell_fn(x *bn254.E12, b *bn254.E6, P *bn254.G1Affine) *bn254.E12 {
	// Compute c0 = b.A0 * P.Y
	var c0 bn254.E2
	c0.MulByElement(&b.B0, &P.Y)

	var c1 bn254.E2

	// Compute c1 = b.A1 * P.X
	c1.MulByElement(&b.B1, &P.X)

	// Compute updated_f = x * (1 + c0 * v^0 + c1 * v^3 + b.A2 * v^4)
	var updated_f bn254.E12
	updated_f = *x
	updated_f.MulBy034(&c0, &c1, &b.B2)

	return &updated_f
}

type G2Projective struct {
	X, Y, Z bn254.E2
}

func LineDouble_fn(R *G2Projective) (*G2Projective, *bn254.E6) {
	// Output variables
	var R_Double G2Projective
	var ell_coeff bn254.E6

	// a = (R.X * R.Y) / 2
	var a_first1 bn254.E2
	a_first1.Mul(&R.X, &R.Y)

	twoInv := *new(fp.Element).SetUint64(2)
	twoInv.Inverse(&twoInv)

	var a bn254.E2
	a.MulByElement(&a_first1, &twoInv)

	// b = R.Y^2
	var b bn254.E2
	b.Mul(&R.Y, &R.Y)

	// c = R.Z^2
	var c bn254.E2
	c.Mul(&R.Z, &R.Z)

	// 3c = 2c + c
	var c2_plus_c bn254.E2
	var c_double bn254.E2
	c_double.Add(&c, &c)
	c2_plus_c.Add(&c_double, &c)

	// COEFF_B (from BN254 twist)
	a0_tempStr := "19485874751759354771024239261021720505790618469301721065564631296452457478373"
	a1_tempStr := "266929791119991161246907387137283842545076965332900288569378510910307636690"
	a0_temp, _ := new(fp.Element).SetString(a0_tempStr)
	a1_temp, _ := new(fp.Element).SetString(a1_tempStr)

	COEFF_B := bn254.E2{
		A0: *a0_temp,
		A1: *a1_temp,
	}

	// f = 3 * COEFF_B * c
	var e_val, f bn254.E2
	e_val.Mul(&COEFF_B, &c2_plus_c)
	var e_double bn254.E2
	e_double.Add(&e_val, &e_val)
	f.Add(&e_double, &e_val)

	// g = (b + f) / 2
	var g bn254.E2
	g.Add(&b, &f)
	g.MulByElement(&g, &twoInv)

	// h = (R.Y + R.Z)^2 - (b + c)
	var h bn254.E2
	var yPlusZ bn254.E2
	yPlusZ.Add(&R.Y, &R.Z)
	h.Mul(&yPlusZ, &yPlusZ)
	var b_plus_c bn254.E2
	b_plus_c.Add(&b, &c)
	h.Sub(&h, &b_plus_c)

	// i = e_val - b
	var i bn254.E2
	i.Sub(&e_val, &b)

	// j = R.X^2
	var j bn254.E2
	j.Mul(&R.X, &R.X)

	// R_Double.X = a * (b - f)
	var b_minus_f bn254.E2
	b_minus_f.Sub(&b, &f)
	R_Double.X.Mul(&a, &b_minus_f)

	// R_Double.Y = g^2 - 3 * e_val^2
	var g_square, e_square, l bn254.E2
	g_square.Mul(&g, &g)
	e_square.Mul(&e_val, &e_val)
	l.Add(&e_square, &e_square)
	l.Add(&l, &e_square)
	R_Double.Y.Sub(&g_square, &l)

	// R_Double.Z = b * h
	R_Double.Z.Mul(&b, &h)

	// Compute ell_coeff
	ell_coeff.B0.A0.Neg(&h.A0)
	ell_coeff.B0.A1.Neg(&h.A1)
	ell_coeff.B1.Add(&j, &j)
	ell_coeff.B1.Add(&ell_coeff.B1, &j) // 3*j
	ell_coeff.B2 = i

	return &R_Double, &ell_coeff
}

func LineAddition_fn(R *G2Projective, Q *bn254.G2Affine) (*G2Projective, *bn254.E6) {
	// Output variables
	var R_New G2Projective
	var ell_coeff bn254.E6

	// theta = R.Y - Q.Y * R.Z
	var Qy_Rz, theta bn254.E2
	Qy_Rz.Mul(&Q.Y, &R.Z)
	theta.Sub(&R.Y, &Qy_Rz)

	// lambda = R.X - Q.X * R.Z
	var Qx_Rz, lambda bn254.E2
	Qx_Rz.Mul(&Q.X, &R.Z)
	lambda.Sub(&R.X, &Qx_Rz)

	// Intermediate calculations
	var c, d, e_val, f, g, h_temp, h bn254.E2
	c.Mul(&theta, &theta)
	d.Mul(&lambda, &lambda)
	e_val.Mul(&lambda, &d)
	f.Mul(&R.Z, &c)
	g.Mul(&R.X, &d)

	var g_double bn254.E2
	g_double.Add(&g, &g)

	h_temp.Add(&e_val, &f)
	h.Sub(&h_temp, &g_double)

	// R_New.X = lambda * h
	R_New.X.Mul(&lambda, &h)

	// R_New.Y = theta * (g - h) - e_val * R.Y
	var g_minus_h, e_Ry, theta_g_minus_h bn254.E2
	g_minus_h.Sub(&g, &h)
	e_Ry.Mul(&e_val, &R.Y)
	theta_g_minus_h.Mul(&theta, &g_minus_h)
	R_New.Y.Sub(&theta_g_minus_h, &e_Ry)

	// R_New.Z = R.Z * e_val
	R_New.Z.Mul(&R.Z, &e_val)

	// ell_coeff
	var theta_Qx, lambda_Qy, j bn254.E2
	theta_Qx.Mul(&theta, &Q.X)
	lambda_Qy.Mul(&lambda, &Q.Y)
	j.Sub(&theta_Qx, &lambda_Qy)

	ell_coeff.B0 = lambda
	ell_coeff.B1.A0.Neg(&theta.A0)
	ell_coeff.B1.A1.Neg(&theta.A1)
	ell_coeff.B2 = j

	return &R_New, &ell_coeff
}

func EllCoeffStep_fn(
	Rin *G2Projective, // R[2*i]
	Q, negQ *bn254.G2Affine, // Q and -Q
	bit int, // {-1, 0, 1}
) (Rmid, Rout G2Projective, ell1, ell2 *bn254.E6) {

	// Step 1: LineDouble
	RmidPtr, ell1Ptr := LineDouble_fn(Rin)
	Rmid = *RmidPtr
	ell1 = ell1Ptr

	// Step 2: LineAddition or Propagation
	if bit == 1 {
		RoutPtr, ell2Ptr := LineAddition_fn(&Rmid, Q)
		Rout = *RoutPtr
		ell2 = ell2Ptr
	} else if bit == -1 {
		RoutPtr, ell2Ptr := LineAddition_fn(&Rmid, negQ)
		Rout = *RoutPtr
		ell2 = ell2Ptr
	} else {
		Rout = Rmid
		ell2 = ell1
	}

	return
}

func ToProjective_fn(A *bn254.G2Affine) G2Projective {
	var out G2Projective

	// Check if A.X and A.Y are zero
	isZeroX := A.X.IsZero()
	isZeroY := A.Y.IsZero()

	if isZeroX && isZeroY {
		// Return the point at infinity in projective coords
		out.X.SetZero()
		out.Y.SetOne()
		out.Z.SetZero()
	} else {
		// Regular conversion
		out.X = A.X
		out.Y = A.Y
		out.Z.SetOne()
	}

	return out
}

func G2ProjectiveFromBNG2Projective(y *G2Projective) groups.G2Projective {
	return groups.G2Projective{
		X: field_tower.FromE2(&y.X),
		Y: field_tower.FromE2(&y.Y),
		Z: field_tower.FromE2(&y.Z),
	}
}

func MulByChar_fn(Q *bn254.G2Affine) *bn254.G2Affine {
	// Constants from BN254 twist parameters
	a0, _ := new(fp.Element).SetString("21575463638280843010398324269430826099269044274347216827212613867836435027261")
	a1, _ := new(fp.Element).SetString("10307601595873709700152284273816112264069230130616436755625194854815875713954")
	TWIST_MUL_BY_Q_X := bn254.E2{
		A0: *a0,
		A1: *a1,
	}

	a00, _ := new(fp.Element).SetString("2821565182194536844548159561693502659359617185244120367078079554186484126554")
	a11, _ := new(fp.Element).SetString("3505843767911556378687030309984248845540243509899259641013678093033130930403")

	TWIST_MUL_BY_Q_Y := bn254.E2{
		A0: *a00,
		A1: *a11,
	}

	// Frobenius map is just conjugation in Fp2 (negate A1)
	t1 := bn254.E2{A0: Q.X.A0, A1: *new(fp.Element).Neg(&Q.X.A1)}
	t2 := bn254.E2{A0: Q.Y.A0, A1: *new(fp.Element).Neg(&Q.Y.A1)}

	// Multiply by constants
	var outX, outY bn254.E2
	outX.Mul(&t1, &TWIST_MUL_BY_Q_X)
	outY.Mul(&t2, &TWIST_MUL_BY_Q_Y)

	return &bn254.G2Affine{
		X: outX,
		Y: outY,
	}
}

func EllCoeffs_fn(Q *bn254.G2Affine) ([]bn254.E6, []G2Projective) {
	const n = 64

	// Initialize arrays
	ell_coeff := make([]bn254.E6, 2*n+2)
	R := make([]G2Projective, 2*n+2)

	// Inverse of 2
	twoInv := new(fp.Element).SetUint64(2)
	twoInv.Inverse(twoInv)

	// Convert Q to projective
	R[0] = ToProjective_fn(Q)

	// Compute -Q
	var neg_Q bn254.G2Affine
	neg_Q.X = Q.X
	neg_Q.Y.A0.Neg(&Q.Y.A0)
	neg_Q.Y.A1.Neg(&Q.Y.A1)

	// bits used in the Miller loop (signed digits from the NAF of loop scalar)
	bits := []int{
		0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
		0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
		-1, 0, 0, 0, 1, 0, 1,
	}

	// Main loop
	for i := 0; i < n; i++ {
		R_New, ell_New := LineDouble_fn(&R[2*i])
		R[2*i+1] = *R_New
		ell_coeff[2*i] = *ell_New

		bit := bits[n-i-1]
		if bit == 1 {
			R_Add, ell_Add := LineAddition_fn(&R[2*i+1], Q)
			R[2*i+2] = *R_Add
			ell_coeff[2*i+1] = *ell_Add
		} else if bit == -1 {
			R_Add, ell_Add := LineAddition_fn(&R[2*i+1], &neg_Q)
			R[2*i+2] = *R_Add
			ell_coeff[2*i+1] = *ell_Add
		} else {
			R[2*i+2] = R[2*i+1]
			ell_coeff[2*i+1] = ell_coeff[2*i]
		}
	}

	// Frobenius twists
	Q1 := MulByChar_fn(Q)
	Q2 := MulByChar_fn(Q1)

	// -Q2
	var Q2_neg bn254.G2Affine
	Q2_neg.X = Q2.X
	Q2_neg.Y.A0.Neg(&Q2.Y.A0)
	Q2_neg.Y.A1.Neg(&Q2.Y.A1)

	// Final additions
	R_Last1, ell_Last1 := LineAddition_fn(&R[2*n], Q1)
	R[2*n+1] = *R_Last1
	ell_coeff[2*n] = *ell_Last1

	_, ell_Last2 := LineAddition_fn(&R[2*n+1], &Q2_neg)
	ell_coeff[2*n+1] = *ell_Last2

	return ell_coeff, R
}

func MillerLoopStep_fn(
	fIn *bn254.E12,
	ell []bn254.E6,
	p *bn254.G1Affine,
	bit int,
) (f1, f2, f3 bn254.E12) {
	// Step 1: f1 = fIn^2
	f1.Mul(fIn, fIn)

	// Step 2: f2 = Ell(f1, ell[0])
	f2 = *Ell_fn(&f1, &ell[0], p)

	// Step 3: Conditionally apply Ell with ell[1]
	if bit == 1 || bit == -1 {
		f3 = *Ell_fn(&f2, &ell[1], p)
	} else {
		f3 = f2
	}

	return
}

func MillerLoopStepIntegrated_fn(
	Rin *G2Projective, // R[2*i]
	Q, negQ *bn254.G2Affine, // Q and -Q
	p *bn254.G1Affine, // affine P
	fIn *bn254.E12, // f[3*i]
	bit int, // {-1, 0, 1}
) (Rout G2Projective, f1, f2, f3 bn254.E12) {

	// Step 1: LineDouble
	RmidPtr, ell1 := LineDouble_fn(Rin)
	Rmid := *RmidPtr

	// Step 2: LineAddition or Propagation
	var ell2 *bn254.E6
	if bit == 1 {
		RoutPtr, ell2Ptr := LineAddition_fn(&Rmid, Q)
		Rout = *RoutPtr
		ell2 = ell2Ptr
	} else if bit == -1 {
		RoutPtr, ell2Ptr := LineAddition_fn(&Rmid, negQ)
		Rout = *RoutPtr
		ell2 = ell2Ptr
	} else {
		Rout = Rmid
		ell2 = ell1
	}

	// Step 3: f1 = fIn^2
	f1.Mul(fIn, fIn)

	// Step 4: f2 = Ell(f1, ell1)
	f2 = *Ell_fn(&f1, ell1, p)

	// Step 5: f3 = Ell(f2, ell2) if bit == ±1
	if bit == 1 || bit == -1 {
		f3 = *Ell_fn(&f2, ell2, p)
	} else {
		f3 = f2
	}

	return
}

func FinalMillerLoopStepIntegrated_fn(
	Rin *G2Projective,
	Q *bn254.G2Affine,
	P *bn254.G1Affine,
	fIn *bn254.E12,
) (Rout G2Projective, f2 bn254.E12) {

	// Step 1: Compute Frobenius twists
	Q1 := MulByChar_fn(Q)
	Q2 := MulByChar_fn(Q1)

	var negQ2 bn254.G2Affine
	negQ2.X = Q2.X
	negQ2.Y.A1.Neg(&Q2.Y.A1)
	negQ2.Y.A0.Neg(&Q2.Y.A0)

	// Step 2: Line addition with Q1
	Rmid, ell1 := LineAddition_fn(Rin, Q1)

	// Step 3: Line addition with -Q2
	RoutPtr, ell2 := LineAddition_fn(Rmid, &negQ2)
	Rout = *RoutPtr

	// Step 4: Apply Ell twice
	f1 := *Ell_fn(fIn, ell1, P)
	f2 = *Ell_fn(&f1, ell2, P)

	return
}
