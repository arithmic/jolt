package groups

import (
	"crypto/rand"
	"github.com/arithmic/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type G1Projective struct {
	X, Y, Z frontend.Variable
}

type G1API struct {
	Api frontend.API
}

func (g G1API) Double(A *G1Projective) *G1Projective {
	b3, _ := g.Api.Compiler().ConstantValue(3 * 3)

	t0 := g.Api.Mul(A.Y, A.Y)
	t1 := g.Api.Mul(8, t0)

	t3 := g.Api.Mul(A.Y, A.Z)
	t4 := g.Api.Mul(A.Z, A.Z)
	t5 := g.Api.Mul(b3, t4)

	t6 := g.Api.Mul(t5, t1)
	t7 := g.Api.Add(t0, t5)
	t8 := g.Api.Mul(t3, t1)

	t9 := g.Api.Mul(2, t5)
	t10 := g.Api.Add(t9, t5)
	t11 := g.Api.Sub(t0, t10)

	t12 := g.Api.Add(t6, g.Api.Mul(t11, t7))
	t13 := g.Api.Mul(A.X, A.Y)
	t14 := g.Api.Mul(2, t11, t13)

	return &G1Projective{
		X: t14,
		Y: t12,
		Z: t8,
	}
}

func (g G1API) Add(A, B *G1Projective) *G1Projective {
	b3, _ := g.Api.Compiler().ConstantValue(3 * 3)

	t0 := g.Api.Mul(A.X, B.X)
	t1 := g.Api.Mul(A.Y, B.Y)
	t2 := g.Api.Mul(A.Z, B.Z)
	t3 := g.Api.Add(A.X, A.Y)
	t4 := g.Api.Add(B.X, B.Y)
	t5 := g.Api.Mul(t3, t4)
	t6 := g.Api.Add(t0, t1)
	t7 := g.Api.Sub(t5, t6)
	t8 := g.Api.Add(A.Y, A.Z)
	t9 := g.Api.Add(B.Y, B.Z)
	t10 := g.Api.Mul(t8, t9)
	t11 := g.Api.Add(t1, t2)
	t12 := g.Api.Sub(t10, t11)
	t13 := g.Api.Add(A.X, A.Z)
	t14 := g.Api.Add(B.X, B.Z)
	t15 := g.Api.Mul(t13, t14)
	t16 := g.Api.Add(t0, t2)
	t17 := g.Api.Sub(t15, t16)
	t18 := g.Api.Add(t0, t0)
	t19 := g.Api.Add(t18, t0)
	t20 := g.Api.Mul(b3, t2)
	t21 := g.Api.Add(t1, t20)
	t22 := g.Api.Sub(t1, t20)
	t23 := g.Api.Mul(b3, t17)
	t24 := g.Api.Mul(t12, t23)
	t25 := g.Api.Mul(t7, t22)
	t26 := g.Api.Sub(t25, t24)
	t27 := g.Api.Mul(t23, t19)
	t28 := g.Api.Mul(t22, t21)
	t29 := g.Api.Add(t28, t27)
	t30 := g.Api.Mul(t19, t7)
	t31 := g.Api.Mul(t21, t12)
	t32 := g.Api.Add(t31, t30)

	return &G1Projective{
		X: t26,
		Y: t29,
		Z: t32,
	}
}

func (g G1API) ScalarMul(A *G1Projective, exp *frontend.Variable) *G1Projective {
	// TODO: Maybe n = 110. Provides enough security and leads to a smaller circuit.
	n := 254
	bits := g.Api.ToBinary(*exp, n)

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

func (g G1API) AssertIsEqual(A, B *G1Projective) {
	g.Api.AssertIsEqual(g.Api.Mul(A.X, B.Z), g.Api.Mul(B.X, A.Z))
	g.Api.AssertIsEqual(g.Api.Mul(A.Y, B.Z), g.Api.Mul(B.Y, A.Z))
}

func (g G1API) Select(bit frontend.Variable, A, B *G1Projective) *G1Projective {
	return &G1Projective{
		X: g.Api.Select(bit, A.X, B.X),
		Y: g.Api.Select(bit, A.Y, B.Y),
		Z: g.Api.Select(bit, A.Z, B.Z),
	}
}

func FromG1Affine(p *bn254.G1Affine) G1Projective {
	if p.X.IsZero() && p.Y.IsZero() {
		var zero, one fr.Element
		zero.SetZero()
		one.SetOne()

		return G1Projective{
			X: zero,
			Y: one,
			Z: zero,
		}
	}

	return G1Projective{
		X: fr.Element(p.X),
		Y: fr.Element(p.Y),
		Z: fr.One(),
	}
}

func RandomG1Affine() bn254.G1Affine {
	_, _, gen, _ := bn254.Generators()
	mod := bn254.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bn254.G1Affine
	p.ScalarMultiplication(&gen, s1)

	return p
}
