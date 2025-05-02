package g1ops

// import (
// 	"github.com/arithmic/gnark/frontend"
// )

// type G1Affine struct {
// 	X, Y frontend.Variable
// }

// type G1 struct {
// 	api frontend.API
// }

// func NewG1(api frontend.API) *G1 {
// 	return &G1{api: api}
// }

// // func (g G1) Add(p, q *G1Affine) *G1Affine {
// // 	// selector1 = 1 when p is (0,0) and 0 otherwise
// // 	selector1 := g.api.And(g.api.IsZero(&p.X), g.api.IsZero(&p.Y))
// // 	// selector2 = 1 when q is (0,0) and 0 otherwise
// // 	selector2 := g.api.And(g.api.IsZero(&q.X), g.api.IsZero(&q.Y))

// // 	// λ = ((p.x+q.x)² - p.x*q.x + a)/(p.y + q.y)
// // 	pxqx := g.api.Mul(&p.X, &q.X)
// // 	pxplusqx := g.api.Add(&p.X, &q.X)
// // 	num := g.api.Mul(pxplusqx, pxplusqx)
// // 	num = g.api.Sub(num, pxqx)
// // 	if g.addA {
// // 		num = g.api.Add(num, &g.a)
// // 	}
// // 	denum := g.api.Add(&p.Y, &q.Y)
// // 	// if p.y + q.y = 0, assign dummy 1 to denum and continue
// // 	selector3 := g.api.IsZero(denum)
// // 	denum = g.api.Select(selector3, g.api.One(), denum)
// // 	λ := g.api.Div(num, denum)

// // 	// x = λ^2 - p.x - q.x
// // 	xr := g.api.Mul(λ, λ)
// // 	xr = g.api.Sub(xr, pxplusqx)

// // 	// y = λ(p.x - xr) - p.y
// // 	yr := g.api.Sub(&p.X, xr)
// // 	yr = g.api.Mul(yr, λ)
// // 	yr = g.api.Sub(yr, &p.Y)
// // 	result := AffinePoint[B]{
// // 		X: *g.api.Reduce(xr),
// // 		Y: *g.api.Reduce(yr),
// // 	}

// // 	zero := g.api.Zero()
// // 	infinity := AffinePoint[B]{X: *zero, Y: *zero}
// // 	// if p=(0,0) return q
// // 	result = *g.Select(selector1, q, &result)
// // 	// if q=(0,0) return p
// // 	result = *g.Select(selector2, p, &result)
// // 	// if p.y + q.y = 0, return (0, 0)
// // 	result = *g.Select(selector3, &infinity, &result)

// // 	return &result
// // }

// // func (g G1) AssertIsEqual(A, B *G1Projective) {
// // 	g.api.AssertIsEqual(A.X, B.X)
// // 	g.api.AssertIsEqual(A.Y, B.Y)
// // }

// // func FromG1Affine(p *bn254.G1Affine) G1Projective {
// // 	return G1Projective{
// // 		X: fr.Element(p.X),
// // 		Y: fr.Element(p.Y),
// // 		// Z: fr.One(),
// // 	}
// // }
