package field_tower

import (
	"github.com/arithmic/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type Fp12 struct {
	A0, A1 Fp6
}

type Ext12 struct {
	e6 Ext6
}

func FromE12(y *bn254.E12) Fp12 {
	return Fp12{
		A0: FromE6(&y.C0),
		A1: FromE6(&y.C1),
	}
}

func (e Ext12) One() *Fp12 {
	return &Fp12{
		A0: *e.e6.One(),
		A1: *e.e6.Zero(),
	}
}

func (e Ext12) Zero() *Fp12 {
	return &Fp12{
		A0: *e.e6.Zero(),
		A1: *e.e6.Zero(),
	}
}

func (e Ext12) Add(x, y *Fp12) *Fp12 {
	z0 := e.e6.Add(&x.A0, &y.A0)
	z1 := e.e6.Add(&x.A1, &y.A1)
	return &Fp12{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext12) Conjugate(x *Fp12) *Fp12 {
	var result Fp12
	result.A0 = x.A0
	result.A1 = *e.e6.Neg(&x.A1)
	return &result
}

func (e Ext12) Mul(x, y *Fp12) *Fp12 {
	// Declare intermediate variables
	var a, b, c Fp6

	// Compute a = (x.A0 + x.A1) * (y.A0 + y.A1)
	a = *e.e6.Add(&x.A0, &x.A1) // a = x.A0 + x.A1
	b = *e.e6.Add(&y.A0, &y.A1) // b = y.A0 + y.A1
	a = *e.e6.Mul(&a, &b)       // a = a * b

	// Compute b = x.A0 * y.A0
	b = *e.e6.Mul(&x.A0, &y.A0)

	// Compute c = x.A1 * y.A1
	c = *e.e6.Mul(&x.A1, &y.A1)

	// Compute z.A1 = a - b - c
	z1 := *e.e6.Sub(&a, &b) // z.A1 = a - b
	z1 = *e.e6.Sub(&z1, &c) // z.A1 = z.A1 - c

	// Compute z.A0 = b + NonResidue * c
	z0 := *e.e6.MulByNonResidue(&c) // z.A0 = NonResidue * c
	z0 = *e.e6.Add(&z0, &b)         // z.A0 = z.A0 + b

	// Return the result
	return &Fp12{
		A0: z0,
		A1: z1,
	}
}

func (e Ext12) Square(x *Fp12) *Fp12 {
	var c0, c2, c3 Fp6

	// Compute c0 = x.A0 - x.A1
	c0 = *e.e6.Sub(&x.A0, &x.A1)

	// Compute c3 = NonResidue * x.A1 - x.A0
	c3 = *e.e6.MulByNonResidue(&x.A1) // c3 = NonResidue * x.A1
	c3 = *e.e6.Neg(&c3)               // c3 = -c3
	c3 = *e.e6.Add(&x.A0, &c3)        // c3 = x.A0 + c3

	// Compute c2 = x.A0 * x.A1
	c2 = *e.e6.Mul(&x.A0, &x.A1)

	// Compute c0 = c0 * c3 + c2
	c0 = *e.e6.Mul(&c0, &c3) // c0 = c0 * c3
	c0 = *e.e6.Add(&c0, &c2) // c0 = c0 + c2

	z1 := *e.e6.Add(&c2, &c2) // z.A1 = c2 + c2

	// Compute z.A0 = c0 + NonResidue * c2
	c2 = *e.e6.MulByNonResidue(&c2) // c2 = NonResidue * c2
	z0 := *e.e6.Add(&c0, &c2)       // z.A0 = c0 + c2

	// Return the result
	return &Fp12{
		A0: z0,
		A1: z1,
	}

}

func (e Ext12) Inverse(x *Fp12) *Fp12 {

	var t0, t1, tmp Fp6
	// Compute t0 = x.A0^2
	t0 = *e.e6.Square(&x.A0)
	// Compute t1 = x.A1^2
	t1 = *e.e6.Square(&x.A1)
	// Compute tmp = NonResidue * t1
	tmp = *e.e6.MulByNonResidue(&t1)
	// Compute t0 = t0 - tmp
	t0 = *e.e6.Sub(&t0, &tmp)
	// Compute t1 = t0^-1 (inverse of t0)
	t1 = *e.e6.Inverse(&t0)
	// Compute z.A0 = x.A0 * t1
	z0 := *e.e6.Mul(&x.A0, &t1)
	// Compute z.A1 = -(x.A1 * t1)
	z1 := *e.e6.Mul(&x.A1, &t1)
	z1 = *e.e6.Neg(&z1)
	// Return the result
	return &Fp12{
		A0: z0,
		A1: z1,
	}
}

func (e Ext12) Select(condition frontend.Variable, a, b *Fp12) *Fp12 {
	// Conditionally select the real part
	z0 := e.e6.Select(condition, &b.A0, &a.A0)
	// Conditionally select the imaginary part
	z1 := e.e6.Select(condition, &b.A1, &a.A1)

	return &Fp12{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext12) Exp(x *Fp12, k *frontend.Variable) *Fp12 {
	const n = 254
	bits := e.e6.e2.api.ToBinary(*k, n)

	z := e.One()
	// Perform binary exponentiation
	for i := n - 1; i >= 0; i-- {
		// Square z
		z = e.Square(z)
		// Conditionally multiply z by x if the current bit is 1
		z = e.Select(bits[i], z, e.Mul(z, x))
	}
	return z
}

func (e Ext12) AssertIsEqual(x, y *Fp12) {
	e.e6.AssertIsEqual(&x.A0, &y.A0)
	e.e6.AssertIsEqual(&x.A1, &y.A1)
}
