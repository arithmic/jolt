package g1ops

import (
	"github.com/arithmic/gnark/frontend"
	fp2 "github.com/arithmic/jolt/jolt-on-chain/algebra/native/bn254/field_tower"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type G2Affine struct {
	X, Y fp2.Fp2
}

type G2 struct {
	e2 fp2.Ext2
}

func NewG2(api frontend.API) *G2 {
	return &G2{e2: fp2.NewExt2(api)}
}

// Warning: Points should be unequal
func (g2 *G2) G2Add(p, q *G2Affine) *G2Affine {
	// λ = (q.Y - p.Y) / (q.X - p.X)
	qypy := g2.e2.Sub(&q.Y, &p.Y)
	qxpx := g2.e2.Sub(&q.X, &p.X)

	// removed unchecked division
	lambda1 := g2.e2.Inverse(qxpx)

	λ := g2.e2.Mul(lambda1, qypy)

	// xr = λ² - p.X - q.X
	lambdaSquared := g2.e2.Mul(λ, λ)
	xr := g2.e2.Sub(lambdaSquared, &p.X)
	xr = g2.e2.Sub(xr, &q.X)

	// yr = λ(p.X - xr) - p.Y
	pxMinusXr := g2.e2.Sub(&p.X, xr)
	lambdaTimesDiff := g2.e2.Mul(λ, pxMinusXr)
	yr := g2.e2.Sub(lambdaTimesDiff, &p.Y)

	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g2 G2) G2Neg(p *G2Affine) *G2Affine {
	xr := &p.X
	yr := g2.e2.Neg(&p.Y)
	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g2 G2) G2Sub(p, q *G2Affine) *G2Affine {
	qNeg := g2.G2Neg(q)
	return g2.G2Add(p, qNeg)
}

func (g2 *G2) G2Double(p *G2Affine) *G2Affine {
	// λ = (3 * p.X^2) / (2 * p.Y)
	_ = frontend.Variable(3)
	three := frontend.Variable(3)
	two := frontend.Variable(2)

	xx := g2.e2.Mul(&p.X, &p.X)               // p.X²
	threeXX := g2.e2.MulByElement(xx, &three) // 3 * p.X²
	twoY := g2.e2.MulByElement(&p.Y, &two)    // 2 * p.Y

	lambda1 := g2.e2.Inverse(twoY)        // 1 / (2 * p.Y)
	lambda := g2.e2.Mul(threeXX, lambda1) // λ

	// xr = λ² - 2*p.X
	lambda2 := g2.e2.Mul(lambda, lambda)   // λ²
	twoX := g2.e2.MulByElement(&p.X, &two) // 2*p.X
	xr := g2.e2.Sub(lambda2, twoX)         // λ² - 2*p.X

	// yr = λ(p.X - xr) - p.Y
	pxMinusXr := g2.e2.Sub(&p.X, xr)            // p.X - xr
	lambdaTimes := g2.e2.Mul(lambda, pxMinusXr) // λ*(p.X - xr)
	yr := g2.e2.Sub(lambdaTimes, &p.Y)          // λ*(p.X - xr) - p.Y

	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g2 *G2) G2DoubleN(p *G2Affine, n int) *G2Affine {
	pn := p
	for s := 0; s < n; s++ {
		pn = g2.G2Double(pn)
	}
	return pn
}

// Warning: Points should be unequal
func (g2 *G2) G2DoubleAndAdd(p, q *G2Affine) *G2Affine {
	// compute λ1 = (q.Y - p.Y) / (q.X - p.X)
	yqyp := g2.e2.Sub(&q.Y, &p.Y)
	xqxp := g2.e2.Sub(&q.X, &p.X)

	λ1_prime := g2.e2.Inverse(xqxp)
	λ1 := g2.e2.Mul(λ1_prime, yqyp)

	// compute x2 = λ1² - p.X - q.X
	lambda1Squared := g2.e2.Mul(λ1, λ1)
	x2 := g2.e2.Sub(lambda1Squared, &p.X)
	x2 = g2.e2.Sub(x2, &q.X)

	// compute -λ2 = λ1 + 2*p.Y / (x2 - p.X)
	twoPy := g2.e2.Double(&p.Y)
	x2xp := g2.e2.Sub(x2, &p.X)
	twoPyOverX2xp := g2.e2.Inverse(x2xp)
	twoPyOverX2xp = g2.e2.Mul(twoPyOverX2xp, twoPy)
	lambda2 := g2.e2.Add(λ1, twoPyOverX2xp)

	// compute x3 = (-λ2)² - p.X - x2
	lambda2Squared := g2.e2.Mul(lambda2, lambda2)
	x3 := g2.e2.Sub(lambda2Squared, &p.X)
	x3 = g2.e2.Sub(x3, x2)

	// compute y3 = -λ2 * (x3 - p.X) - p.Y
	x3xp := g2.e2.Sub(x3, &p.X)

	y3 := g2.e2.Mul(lambda2, x3xp)
	y3 = g2.e2.Sub(y3, &p.Y)

	return &G2Affine{
		X: *x3,
		Y: *y3,
	}
}

func (g2 *G2) G2scalarMulBySeed(q *G2Affine) *G2Affine {
	z := g2.G2Double(q)
	t0 := g2.G2Add(q, z)
	t2 := g2.G2Add(q, t0)
	t1 := g2.G2Add(z, t2)
	z = g2.G2DoubleAndAdd(t1, t0)
	t0 = g2.G2Add(t0, z)
	t2 = g2.G2Add(t2, t0)
	t1 = g2.G2Add(t1, t2)
	t0 = g2.G2Add(t0, t1)
	t1 = g2.G2Add(t1, t0)
	t0 = g2.G2Add(t0, t1)
	t2 = g2.G2Add(t2, t0)
	t1 = g2.G2DoubleAndAdd(t2, t1)
	t2 = g2.G2Add(t2, t1)
	z = g2.G2Add(z, t2)
	t2 = g2.G2Add(t2, z)
	z = g2.G2DoubleAndAdd(t2, z)
	t0 = g2.G2Add(t0, z)
	t1 = g2.G2Add(t1, t0)
	t3 := g2.G2Double(t1)
	t3 = g2.G2DoubleAndAdd(t3, t1)
	t2 = g2.G2Add(t2, t3)
	t1 = g2.G2Add(t1, t2)
	t2 = g2.G2Add(t2, t1)
	t2 = g2.G2DoubleN(t2, 16)
	t1 = g2.G2DoubleAndAdd(t2, t1)
	t1 = g2.G2DoubleN(t1, 13)
	t0 = g2.G2DoubleAndAdd(t1, t0)
	t0 = g2.G2DoubleN(t0, 15)
	z = g2.G2DoubleAndAdd(t0, z)

	return z
}

func (e G2) AssertIsEqual(p, q *G2Affine) {
	e.e2.AssertIsEqual(&p.X, &q.X)
	e.e2.AssertIsEqual(&p.Y, &q.Y)
}

func FromBNG2Affine(y *bn254.G2Affine) G2Affine {
	return G2Affine{
		X: fp2.FromE2(&y.X),
		Y: fp2.FromE2(&y.Y),
	}
}
