package groups

import (
	"crypto/rand"
	"math/big"

	"github.com/arithmic/gnark/frontend"
	fp2 "github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"
	"github.com/consensys/gnark-crypto/ecc/bn254"
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

	res := G2Projective{
		X: *g2.e2.Zero(),
		Y: *g2.e2.One(),
		Z: *g2.e2.Zero(),
	}

	for i := 0; i < n; i++ {
		dbl := g2.Double(&res)
		add := g2.Add(dbl, P)

		res = *g2.Select(bits[n-1-i], add, dbl)
	}

	return &res
}

func (g2 *G2API) ToProjective(A *G2Affine) *G2Projective {
	i1 := g2.e2.IsZero(&A.X)
	i2 := g2.e2.IsZero(&A.Y)
	i := g2.api.Mul(i1, i2)

	projective_identity := G2Projective{
		X: *g2.e2.Zero(),
		Y: *g2.e2.One(),
		Z: *g2.e2.Zero(),
	}
	out := *g2.Select(i, &projective_identity, &G2Projective{
		X: A.X,
		Y: A.Y,
		Z: *g2.e2.One(),
	})
	return &out
}

// AssertIsEqual checks if two G2 projective points are equal.
func (e G2API) AssertIsEqual(p, q *G2Projective) {
	e.e2.AssertIsEqual(e.e2.Mul(&p.X, &q.Z), e.e2.Mul(&q.X, &p.Z))
	e.e2.AssertIsEqual(e.e2.Mul(&p.Y, &q.Z), e.e2.Mul(&q.Y, &p.Z))
}

// This is just for testing purposes, its working with the non identity element in this form,
// to test ToProjective for identity element, we have to change A0 to 0 instead of 1.
func FromBNG2Affine(y *bn254.G2Affine) G2Projective {
	return G2Projective{
		X: fp2.FromE2(&y.X),
		Y: fp2.FromE2(&y.Y),
		Z: fp2.Fp2{
			A0: frontend.Variable(1),
			A1: frontend.Variable(0),
		},
	}
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
