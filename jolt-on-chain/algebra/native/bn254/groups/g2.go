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

func (g2 *G2) Add(p, q *G2Affine) *G2Affine {
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
