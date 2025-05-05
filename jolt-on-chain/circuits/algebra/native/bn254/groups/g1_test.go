package groups

import (
	"crypto/rand"
	"testing"

	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/test"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fp"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

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

type G1DoubleCircuit struct {
	A, C G1Projective
}

func (circuit *G1DoubleCircuit) Define(api frontend.API) error {
	g := &G1API{api: api}
	result := g.Double(&circuit.A)
	g.AssertIsEqual(result, &circuit.C)
	return nil
}

func TestCircuitG1Double(t *testing.T) {
	assert := test.NewAssert(t)

	var a, c bn254.G1Affine

	a = RandomG1Affine()
	c.Double(&a)

	witness := G1DoubleCircuit{
		A: FromG1Affine(&a),
		C: FromG1Affine(&c),
	}

	err := test.IsSolved(&G1DoubleCircuit{}, &witness, ecc.GRUMPKIN.ScalarField())
	assert.NoError(err)
}

type G1AddCircuit struct {
	A, B, C G1Projective
}

func (circuit *G1AddCircuit) Define(api frontend.API) error {
	g := &G1API{api: api}
	result := g.Add(&circuit.A, &circuit.B)
	g.AssertIsEqual(result, &circuit.C)
	return nil
}

func TestCircuitG1Add(t *testing.T) {
	assert := test.NewAssert(t)

	var a, b, c bn254.G1Affine

	a = RandomG1Affine()
	b = RandomG1Affine()
	c.Add(&a, &b)

	witness := G1AddCircuit{
		A: FromG1Affine(&a),
		B: FromG1Affine(&b),
		C: FromG1Affine(&c),
	}

	err := test.IsSolved(&G1AddCircuit{}, &witness, ecc.GRUMPKIN.ScalarField())
	assert.NoError(err)
}

type G1ScalarMulCircuit struct {
	A, C G1Projective
	Exp  frontend.Variable
}

func (circuit *G1ScalarMulCircuit) Define(api frontend.API) error {
	g := &G1API{api: api}
	result := g.ScalarMul(&circuit.A, &circuit.Exp)
	g.AssertIsEqual(result, &circuit.C)
	return nil
}

func TestCircuitG1ScalarMul(t *testing.T) {
	assert := test.NewAssert(t)

	var a, c bn254.G1Affine
	a = RandomG1Affine()

	b_big, _ := rand.Int(rand.Reader, fp.Modulus())

	var b1 fr.Element
	b1.SetBigInt(b_big)

	c.ScalarMultiplication(&a, b_big)

	witness := G1ScalarMulCircuit{
		A:   FromG1Affine(&a),
		Exp: b1,
		C:   FromG1Affine(&c),
	}

	err := test.IsSolved(&G1ScalarMulCircuit{}, &witness, ecc.GRUMPKIN.ScalarField())
	assert.NoError(err)
}