package g1ops

import (
	"github.com/arithmic/gnark/frontend"
)

type G1Projective struct {
	X, Y, Z frontend.Variable
}

type G1 struct {
	api frontend.API
}

func (g G1) Double(A *G1Projective) *G1Projective {
	b3, _ := g.api.Compiler().ConstantValue(3 * 3)

	g0 := g.api.Mul(A.Y, A.Y)
	z3 := g.api.Mul(8, g0)

	g1 := g.api.Mul(A.Y, A.Z)
	g2 := g.api.Mul(A.Z, A.Z)
	g3 := g.api.Mul(b3, g2)

	x3 := g.api.Mul(g3, z3)
	y3 := g.api.Add(g0, g3)
	outZ := g.api.Mul(g1, z3)

	t1 := g.api.Mul(2, g3)
	t2 := g.api.Add(t1, g3)
	t0 := g.api.Sub(g0, t2)

	outY := g.api.Add(x3, g.api.Mul(t0, y3))
	r1 := g.api.Mul(A.X, A.Y)
	outx := g.api.Mul(2, t0, r1)

	return &G1Projective{
		X: outx,
		Y: outY,
		Z: outZ,
	}
}

func (g G1) Add(A, B *G1Projective) *G1Projective {
	b3, _ := g.api.Compiler().ConstantValue(3 * 3)

	t0 := g.api.Mul(A.X, B.X)
	t1 := g.api.Mul(A.Y, B.Y)
	t2 := g.api.Mul(A.Z, B.Z)
	t3 := g.api.Add(A.X, A.Y)
	t4 := g.api.Add(B.X, B.Y)
	t5 := g.api.Mul(t3, t4)
	t6 := g.api.Add(t0, t1)
	t7 := g.api.Sub(t5, t6)
	t8 := g.api.Add(A.Y, A.Z)
	t9 := g.api.Add(B.Y, B.Z)
	t10 := g.api.Mul(t8, t9)
	t11 := g.api.Add(t1, t2)
	t12 := g.api.Sub(t10, t11)
	t13 := g.api.Add(A.X, A.Z)
	t14 := g.api.Add(B.X, B.Z)
	t15 := g.api.Mul(t13, t14)
	t16 := g.api.Add(t0, t2)
	t17 := g.api.Sub(t15, t16)
	t18 := g.api.Add(t0, t0)
	t19 := g.api.Add(t18, t0)
	t20 := g.api.Mul(b3, t2)
	t21 := g.api.Add(t1, t20)
	t22 := g.api.Sub(t1, t20)
	t23 := g.api.Mul(b3, t17)
	t24 := g.api.Mul(t12, t23)
	t25 := g.api.Mul(t7, t22)
	t26 := g.api.Sub(t25, t24)
	t27 := g.api.Mul(t23, t19)
	t28 := g.api.Mul(t22, t21)
	t29 := g.api.Add(t28, t27)
	t30 := g.api.Mul(t19, t7)
	t31 := g.api.Mul(t21, t12)
	t32 := g.api.Add(t31, t30)

	return &G1Projective{
		X: t26,
		Y: t29,
		Z: t32,
	}
}

func (g G1) ScalarMul(A *G1Projective, exp *frontend.Variable) *G1Projective {
	n := 254
	bits := g.api.ToBinary(*exp, n)

	result := &G1Projective{
		X: frontend.Variable(0),
		Y: frontend.Variable(1),
		Z: frontend.Variable(0),
	}

	for i := 0; i < n; i++ {
		doubled := g.Double(result)
		added := g.Add(doubled, A)

		result = g.Select(bits[n-i-1], added, doubled)
	}

	return result
}

func (g G1) AssertIsEqual(A, B *G1Projective) {
	g.api.AssertIsEqual(g.api.Mul(A.X, B.Z), g.api.Mul(B.X, A.Z))
	g.api.AssertIsEqual(g.api.Mul(A.Y, B.Z), g.api.Mul(B.Y, A.Z))
}

func (g G1) Select(bit frontend.Variable, A, B *G1Projective) *G1Projective {
	return &G1Projective{
		X: g.api.Select(bit, A.X, B.X),
		Y: g.api.Select(bit, A.Y, B.Y),
		Z: g.api.Select(bit, A.Z, B.Z),
	}
}
