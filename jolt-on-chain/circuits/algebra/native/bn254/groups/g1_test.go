package g1ops

import (
	"testing"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/test"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type G1Double struct {
	A, C G1Projective
}

func (circuit *G1Double) Define(api frontend.API) error {
	g := &G1{api: api}
	expected := g.Double(&circuit.A)
	expected.X = api.Div(expected.X, expected.Z)
	expected.Y = api.Div(expected.Y, expected.Z)
	expected.Z = fr.One()
	g.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestG1Double(t *testing.T) {
	assert := test.NewAssert(t)

	// witness values
	var a, c bn254.G1Affine
	_, _, gen, _ := bn254.Generators()

	gen.Double(&gen)
	a.Set(&gen)
	gen.Double(&gen)
	c.Set(&gen)

	witness1 := G1Double{
		A: FromG1Affine(&a),
		C: FromG1Affine(&c),
	}

	err := test.IsSolved(&G1Double{}, &witness1, ecc.GRUMPKIN.ScalarField())
	assert.NoError(err)
}

type G1Add struct {
	A, B, C G1Projective
}

func (circuit *G1Add) Define(api frontend.API) error {
	g := &G1{api: api}
	expected := g.Add(&circuit.A, &circuit.B)
	expected.X = api.Div(expected.X, expected.Z)
	expected.Y = api.Div(expected.Y, expected.Z)
	expected.Z = fr.One()
	g.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestG1Add(t *testing.T) {
	assert := test.NewAssert(t)

	// witness values
	var a, b, c bn254.G1Affine
	_, _, gen, _ := bn254.Generators()

	gen.Double(&gen)
	a.Set(&gen)
	gen.Double(&gen)
	b.Set(&gen)

	c.Add(&a, &b)

	witness1 := G1Add{
		A: FromG1Affine(&a),
		B: FromG1Affine(&b),
		C: FromG1Affine(&c),
	}

	err := test.IsSolved(&G1Add{}, &witness1, ecc.GRUMPKIN.ScalarField())
	assert.NoError(err)
}
