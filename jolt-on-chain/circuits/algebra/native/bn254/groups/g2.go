package groups

import (
	"crypto/rand"
	"math/big"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"
	fp2 "github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type G2Projective struct {
	X, Y, Z fp2.Fp2
}

type G2Affine struct {
	X, Y fp2.Fp2
}

type G2API struct {
	e2  fp2.Ext2
	api frontend.API
}

func New(api frontend.API) *G2API {
	return &G2API{e2: *fp2.New(api),
		api: api}
}

// Add performs addition of two G2 projective points in the constraint system.
func (g2 *G2API) Add(P, Q *G2Projective) *G2Projective {
	var b, three fp2.Fp2
	var R G2Projective

	// Constants
	b0, _ := new(big.Int).SetString("19485874751759354771024239261021720505790618469301721065564631296452457478373", 10)
	b1, _ := new(big.Int).SetString("266929791119991161246907387137283842545076965332900288569378510910307636690", 10)

	b.A0 = frontend.Variable(b0)
	b.A1 = frontend.Variable(b1)

	three.A0 = frontend.Variable(3)
	three.A1 = frontend.Variable(0)

	b3 := *g2.e2.Mul(&b, &three)

	t0 := *g2.e2.Mul(&P.X, &Q.X)
	t1 := *g2.e2.Mul(&P.Y, &Q.Y)
	t2 := *g2.e2.Mul(&P.Z, &Q.Z)

	t3 := *g2.e2.Add(&P.X, &P.Y)
	t4 := *g2.e2.Add(&Q.X, &Q.Y)
	t5 := *g2.e2.Mul(&t3, &t4)
	t6 := *g2.e2.Add(&t0, &t1)
	t7 := *g2.e2.Sub(&t5, &t6)

	t8 := *g2.e2.Add(&P.Y, &P.Z)
	t9 := *g2.e2.Add(&Q.Y, &Q.Z)
	t10 := *g2.e2.Mul(&t8, &t9)
	t11 := *g2.e2.Add(&t1, &t2)
	t12 := *g2.e2.Sub(&t10, &t11)

	t13 := *g2.e2.Add(&P.X, &P.Z)
	t14 := *g2.e2.Add(&Q.X, &Q.Z)
	t15 := *g2.e2.Mul(&t13, &t14)
	t16 := *g2.e2.Add(&t0, &t2)
	t17 := *g2.e2.Sub(&t15, &t16)

	t18 := *g2.e2.Add(&t0, &t0)
	t19 := *g2.e2.Add(&t18, &t0)

	t20 := *g2.e2.Mul(&b3, &t2)
	t21 := *g2.e2.Add(&t1, &t20)
	t22 := *g2.e2.Sub(&t1, &t20)

	t23 := *g2.e2.Mul(&b3, &t17)
	t24 := *g2.e2.Mul(&t12, &t23)
	t25 := *g2.e2.Mul(&t7, &t22)
	t26 := *g2.e2.Sub(&t25, &t24)

	t27 := *g2.e2.Mul(&t23, &t19)
	t28 := *g2.e2.Mul(&t22, &t21)
	t29 := *g2.e2.Add(&t27, &t28)

	t30 := *g2.e2.Mul(&t19, &t7)
	t31 := *g2.e2.Mul(&t21, &t12)
	t32 := *g2.e2.Add(&t31, &t30)

	R.X = t26
	R.Y = t29
	R.Z = t32

	return &R
}

// Double performs point doubling on a G2 projective point.
func (g2 *G2API) Double(P *G2Projective) *G2Projective {
	var b, three, two, eight fp2.Fp2
	var R G2Projective

	// Constants
	b_a0, _ := new(big.Int).SetString("19485874751759354771024239261021720505790618469301721065564631296452457478373", 10)
	b.A0 = frontend.Variable(b_a0)

	b_a1, _ := new(big.Int).SetString("266929791119991161246907387137283842545076965332900288569378510910307636690", 10)
	b.A1 = frontend.Variable(b_a1)

	three.A0 = frontend.Variable(3)
	three.A1 = frontend.Variable(0)

	two.A0 = frontend.Variable(2)
	two.A1 = frontend.Variable(0)

	eight.A0 = frontend.Variable(8)
	eight.A1 = frontend.Variable(0)

	// b3 = 3 * b
	b3 := *g2.e2.Mul(&b, &three)

	// g0 = op1.Y^2
	g0 := *g2.e2.Square(&P.Y)

	// z3 = 8 * g0
	z3 := *g2.e2.Mul(&eight, &g0)

	// g1 = op1.Y * op1.Z
	g1 := *g2.e2.Mul(&P.Y, &P.Z)

	// g2_ = op1.Z^2
	g2_ := *g2.e2.Square(&P.Z)

	// g3 = b3 * g2_
	g3 := *g2.e2.Mul(&b3, &g2_)

	// x3 = g3 * z3
	x3 := *g2.e2.Mul(&g3, &z3)

	// y3 = g0 + g3
	y3 := *g2.e2.Add(&g0, &g3)

	// out.Z = g1 * z3
	R.Z = *g2.e2.Mul(&g1, &z3)

	// t1 = 2 * g3
	t1 := *g2.e2.Mul(&two, &g3)

	// t2 = t1 + g3
	t2 := *g2.e2.Add(&t1, &g3)

	// t0 = g0 - t2
	t0 := *g2.e2.Sub(&g0, &t2)

	// t3 = y3 * t0
	t3 := *g2.e2.Mul(&y3, &t0)

	// out.Y = t3 + x3
	R.Y = *g2.e2.Add(&t3, &x3)

	// r1 = op1.X * op1.Y
	r1 := *g2.e2.Mul(&P.X, &P.Y)

	// r2 = t0 * r1
	r2 := *g2.e2.Mul(&t0, &r1)

	// out.X = 2 * r2
	R.X = *g2.e2.Mul(&two, &r2)

	return &R
}

// TODO: Maybe n = 110. Provides enough security and leads to a smaller circuit."
// Mul performs scalar multiplication on a G2 point with a scalar in the constraint system.
func (g2 *G2API) Mul(P *G2Projective, exp *frontend.Variable) *G2Projective {
	const n = 254

	bits := g2.api.ToBinary(*exp, n)

	// Identity point (0, 1, 0)
	zero := frontend.Variable(0)
	one := frontend.Variable(1)

	zeroFp2 := fp2.Fp2{A0: zero, A1: zero}
	oneFp2 := fp2.Fp2{A0: one, A1: zero}

	res := G2Projective{
		X: zeroFp2,
		Y: oneFp2,
		Z: zeroFp2,
	}

	for i := 0; i < n; i++ {
		dbl := g2.Double(&res)
		add := g2.Add(dbl, P)

		res = *g2.Select(bits[n-1-i], add, dbl)
	}

	return &res
}

func (g2 *G2API) ToProjective(A *G2Affine) *G2Projective {
	const n = 256
	var out G2Projective

	// Decompose each Fp2 component into bits
	xA0Bits := g2.api.ToBinary(A.X.A0, n)
	xA1Bits := g2.api.ToBinary(A.X.A1, n)
	yA0Bits := g2.api.ToBinary(A.Y.A0, n)
	yA1Bits := g2.api.ToBinary(A.Y.A1, n)

	comp := func(bits []frontend.Variable) []frontend.Variable {
		out := make([]frontend.Variable, len(bits))
		for i := 0; i < len(bits); i++ {
			out[i] = g2.api.Sub(1, bits[i])
		}
		return out
	}

	xA0Bits = comp(xA0Bits)
	xA1Bits = comp(xA1Bits)
	yA0Bits = comp(yA0Bits)
	yA1Bits = comp(yA1Bits)

	// Compute product of complements
	prod := func(bits []frontend.Variable) frontend.Variable {
		acc := bits[0]
		for i := 1; i < len(bits); i++ {
			acc = g2.api.Mul(acc, bits[i])
		}
		return acc
	}

	xA0Zero := prod(xA0Bits)
	xA1Zero := prod(xA1Bits)
	yA0Zero := prod(yA0Bits)
	yA1Zero := prod(yA1Bits)

	identityIndicator := g2.api.Mul(xA0Zero, g2.api.Mul(xA1Zero, g2.api.Mul(yA0Zero, yA1Zero)))

	projective_identity := G2Projective{
		X: fp2.Fp2{
			A0: frontend.Variable(0),
			A1: frontend.Variable(0),
		},
		Y: fp2.Fp2{
			A0: frontend.Variable(1),
			A1: frontend.Variable(0),
		},
		Z: fp2.Fp2{
			A0: frontend.Variable(0),
			A1: frontend.Variable(0),
		},
	}

	out = *g2.Select(identityIndicator, &projective_identity, &G2Projective{
		X: A.X,
		Y: A.Y,
		Z: fp2.Fp2{
			A0: frontend.Variable(1),
			A1: frontend.Variable(0),
		}})
	return &out
}

// AssertIsEqual checks if two G2 projective points are equal.
func (e G2API) AssertIsEqual(p, q *G2Projective) {
	e.e2.AssertIsEqual(e.e2.Mul(&p.X, &q.Z), e.e2.Mul(&q.X, &p.Z))
	e.e2.AssertIsEqual(e.e2.Mul(&p.Y, &q.Z), e.e2.Mul(&q.Y, &p.Z))
}

// Now it works for both identity and non identity element
func FromBNG2Affine(y *bn254.G2Affine) G2Projective {
	var proj G2Projective

	proj.X = fp2.FromE2(&y.X)
	proj.Y = fp2.FromE2(&y.Y)

	var one fr.Element
	one.SetOne()

	var zero fr.Element
	zero.SetZero()

	if y.X.IsZero() && y.Y.IsZero() {
		// The affine point is identity → projective Z = 0
		proj.Z = fp2.Fp2{
			A0: zero,
			A1: zero,
		}
	} else {
		proj.Z = fp2.Fp2{
			A0: one,
			A1: zero,
		}
	}

	return proj
}
func G2AffineFromBNG2Affine(y *bn254.G2Affine) G2Affine {
	return G2Affine{
		X: fp2.FromE2(&y.X),
		Y: fp2.FromE2(&y.Y),
	}
}

func (g2 G2API) Select(bit frontend.Variable, A, B *G2Projective) *G2Projective {
	return &G2Projective{
		X: *g2.e2.Select(bit, &A.X, &B.X),
		Y: *g2.e2.Select(bit, &A.Y, &B.Y),
		Z: *g2.e2.Select(bit, &A.Z, &B.Z),
	}
}

func RandomG1G2Affines() (bn254.G1Affine, bn254.G2Affine) {
	_, _, G1AffGen, G2AffGen := bn254.Generators()
	mod := bn254.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}

	var p bn254.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bn254.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

// To_Bn254G2Affine converts a G2Projective point to a bn254.G2Affine point.
func To_Bn254G2Affine(p G2Projective) bn254.G2Affine {
	var affine bn254.G2Affine
	affine.X = field_tower.ToE2(p.X)
	affine.Y = field_tower.ToE2(p.Y)

	z_element := field_tower.ToE2(p.Z)

	if z_element.IsZero() {
		affine.X.SetZero()
		affine.Y.SetZero()
		return affine
	} else {
		var z_element_inverse bn254.E2
		z_element_inverse.Inverse(&z_element)
		affine.X.Mul(&affine.X, &z_element_inverse)
		affine.Y.Mul(&affine.Y, &z_element_inverse)
		return affine
	}
}
