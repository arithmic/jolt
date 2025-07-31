package groups

import (
	"crypto/rand"
	"math/big"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/utils"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type G1Projective struct {
	X, Y, Z frontend.Variable
}

type G1API struct {
	api frontend.API
}

type G1Affine struct {
	X, Y frontend.Variable
}

func (g G1API) ToAffine(A *G1Projective) *G1Affine {

	z_is_zero := g.api.IsZero(A.Z)
	inv_val := g.api.Inverse(g.api.Add(g.api.Mul(A.Z, g.api.Sub(frontend.Variable(1), z_is_zero)), z_is_zero))
	z_inv := g.api.Select(g.api.IsZero(A.Z), frontend.Variable(0), inv_val)

	// Compute the affine coordinates
	resX := g.api.Mul(A.X, z_inv)
	resY := g.api.Mul(A.Y, z_inv)

	return &G1Affine{
		X: resX,
		Y: resY,
	}

}

func NewG1API(api frontend.API) *G1API {
	return &G1API{api: api}
}

func (g G1API) Double(A *G1Projective) *G1Projective {
	b3, _ := g.api.Compiler().ConstantValue(3 * 3)

	t0 := g.api.Mul(A.Y, A.Y)
	t1 := g.api.Mul(8, t0)

	t3 := g.api.Mul(A.Y, A.Z)
	t4 := g.api.Mul(A.Z, A.Z)
	t5 := g.api.Mul(b3, t4)

	t6 := g.api.Mul(t5, t1)
	t7 := g.api.Add(t0, t5)
	t8 := g.api.Mul(t3, t1)

	t9 := g.api.Mul(2, t5)
	t10 := g.api.Add(t9, t5)
	t11 := g.api.Sub(t0, t10)

	t12 := g.api.Add(t6, g.api.Mul(t11, t7))
	t13 := g.api.Mul(A.X, A.Y)
	t14 := g.api.Mul(2, t11, t13)

	return &G1Projective{
		X: t14,
		Y: t12,
		Z: t8,
	}
}

func (g G1API) Add(A, B *G1Projective) *G1Projective {
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

func (g G1API) ScalarMul(A *G1Projective, exp *frontend.Variable) *G1Projective {
	// TODO: Maybe n = 110. Provides enough security and leads to a smaller circuit.
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

func (g G1API) AssertIsEqual(A, B *G1Projective) {
	g.api.AssertIsEqual(g.api.Mul(A.X, B.Z), g.api.Mul(B.X, A.Z))
	g.api.AssertIsEqual(g.api.Mul(A.Y, B.Z), g.api.Mul(B.Y, A.Z))
}

func (g G1API) AssertIsEqualAffinePoints(A, B *G1Affine) {
	g.api.AssertIsEqual(A.X, B.X)
	g.api.AssertIsEqual(A.Y, B.Y)
}

func (g G1API) Select(bit frontend.Variable, A, B *G1Projective) *G1Projective {
	return &G1Projective{
		X: g.api.Select(bit, A.X, B.X),
		Y: g.api.Select(bit, A.Y, B.Y),
		Z: g.api.Select(bit, A.Z, B.Z),
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

func AffineFromG1Affine(p *bn254.G1Affine) G1Affine {
	return G1Affine{
		X: fr.Element(p.X),
		Y: fr.Element(p.Y),
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

func To_Bn254G1Affine(p G1Projective) bn254.G1Affine {
	var affine bn254.G1Affine
	x, _ := utils.FrontendVariableToFrElement(p.X)
	y, _ := utils.FrontendVariableToFrElement(p.Y)
	z, _ := utils.FrontendVariableToFrElement(p.Z)

	affine.X = fp.Element{}
	affine.Y = fp.Element{}
	affine.X.SetBigInt(x.BigInt(new(big.Int)))
	affine.Y.SetBigInt(y.BigInt(new(big.Int)))
	var Z fp.Element
	Z.SetBigInt(z.BigInt(new(big.Int)))

	if Z.IsZero() {
		affine.X.SetZero()
		affine.Y.SetZero()
	} else {
		Z.Inverse(&Z)
		affine.X.Mul(&affine.X, &Z)
		affine.Y.Mul(&affine.Y, &Z)
	}
	return affine

}
