package g1ops

import (
	"crypto/rand"
	// "fmt"
	// "math/big"
	"testing"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/test"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type G1Double struct {
	A, C G1Projective
}

func (circuit *G1Double) Define(api frontend.API) error {
	g := &G1{api: api}
	result := g.Double(&circuit.A)
	g.AssertIsEqual(result, &circuit.C)
	return nil
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

func TestG1Double(t *testing.T) {
	assert := test.NewAssert(t)

	var a, c bn254.G1Affine

	a = RandomG1Affine()
	c.Double(&a)

	witness := G1Double{
		A: FromG1Affine(&a),
		C: FromG1Affine(&c),
	}

	err := test.IsSolved(&G1Double{}, &witness, ecc.GRUMPKIN.ScalarField())
	assert.NoError(err)
}

type G1Add struct {
	A, B, C G1Projective
}

func (circuit *G1Add) Define(api frontend.API) error {
	g := &G1{api: api}
	result := g.Add(&circuit.A, &circuit.B)
	g.AssertIsEqual(result, &circuit.C)
	return nil
}

func TestG1Add(t *testing.T) {
	assert := test.NewAssert(t)

	var a, b, c bn254.G1Affine

	a = RandomG1Affine()
	b = RandomG1Affine()
	c.Add(&a, &b)

	witness := G1Add{
		A: FromG1Affine(&a),
		B: FromG1Affine(&b),
		C: FromG1Affine(&c),
	}

	err := test.IsSolved(&G1Add{}, &witness, ecc.GRUMPKIN.ScalarField())
	assert.NoError(err)
}

type G1ScalarMul struct {
	A, C G1Projective
	Exp  frontend.Variable
}

func (circuit *G1ScalarMul) Define(api frontend.API) error {
	g := &G1{api: api}
	result := g.ScalarMul(&circuit.A, &circuit.Exp)
	g.AssertIsEqual(result, &circuit.C)
	return nil
}

func TestG1ScalarMul(t *testing.T) {
	assert := test.NewAssert(t)

	var a, c bn254.G1Affine
	a = RandomG1Affine()

	b_big, _ := rand.Int(rand.Reader, fp.Modulus())

	var b1 fr.Element
	b1.SetBigInt(b_big)

	c.ScalarMultiplication(&a, b_big)

	witness := G1ScalarMul{
		A:   FromG1Affine(&a),
		Exp: b1,
		C:   FromG1Affine(&c),
	}

	err := test.IsSolved(&G1ScalarMul{}, &witness, ecc.GRUMPKIN.ScalarField())
	assert.NoError(err)
}

func FromG1Affine(p *bn254.G1Affine) G1Projective {
	return G1Projective{
		X: fr.Element(p.X),
		Y: fr.Element(p.Y),
		Z: fr.One(),
	}
}
