package field_tower

import (
	"github.com/arithmic/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type Fp6 struct {
	A0, A1, A2 Fp2
}

type Ext6 struct {
	e2 Ext2
}

// NewExt6 creates a new instance of Ext6
func NewExt6(api frontend.API) *Ext6 {
	return &Ext6{e2: Ext2{api: api}}
}

// FromE6 This function is required to create an object of Fp6 from an object of E6 provided by gnark-crypto/ecc/bn254/bn254.go/E6.
// It comes in handy when we want to create random elements of Fp6
func FromE6(y *bn254.E6) Fp6 {
	return Fp6{
		A0: FromE2(&y.B0),
		A1: FromE2(&y.B1),
		A2: FromE2(&y.B2),
	}
}

func (e Ext6) One() *Fp6 {
	return &Fp6{
		A0: Fp2{A0: frontend.Variable(1), A1: frontend.Variable(0)},
		A1: Fp2{A0: frontend.Variable(0), A1: frontend.Variable(0)},
		A2: Fp2{A0: frontend.Variable(0), A1: frontend.Variable(0)},
	}
}

func (e Ext6) Zero() *Fp6 {
	return &Fp6{
		A0: Fp2{A0: frontend.Variable(0), A1: frontend.Variable(0)},
		A1: Fp2{A0: frontend.Variable(0), A1: frontend.Variable(0)},
		A2: Fp2{A0: frontend.Variable(0), A1: frontend.Variable(0)},
	}
}

func (e Ext6) Add(x, y *Fp6) *Fp6 {
	z0 := e.e2.Add(&x.A0, &y.A0)
	z1 := e.e2.Add(&x.A1, &y.A1)
	z2 := e.e2.Add(&x.A2, &y.A2)
	return &Fp6{
		A0: *z0,
		A1: *z1,
		A2: *z2,
	}
}

func (e Ext6) Double(x *Fp6) *Fp6 {
	// Create a new Fp6 to store the result
	var result Fp6

	// Double each component of Fp6
	result.A0 = *e.e2.Double(&x.A0) // A0 = 2 * x.A0
	result.A1 = *e.e2.Double(&x.A1) // A1 = 2 * x.A1
	result.A2 = *e.e2.Double(&x.A2) // A2 = 2 * x.A2

	return &result
}

func (e Ext6) Sub(x, y *Fp6) *Fp6 {
	z0 := e.e2.Sub(&x.A0, &y.A0)
	z1 := e.e2.Sub(&x.A1, &y.A1)
	z2 := e.e2.Sub(&x.A2, &y.A2)
	return &Fp6{
		A0: *z0,
		A1: *z1,
		A2: *z2,
	}
}

func (e Ext6) Neg(x *Fp6) *Fp6 {
	z0 := e.e2.Neg(&x.A0)
	z1 := e.e2.Neg(&x.A1)
	z2 := e.e2.Neg(&x.A2)
	return &Fp6{
		A0: *z0,
		A1: *z1,
		A2: *z2,
	}
}

func (e Ext6) Mul(x, y *Fp6) *Fp6 {
	var t0, t1, t2, c0, c1, c2, tmp Fp2

	// Compute t0, t1, t2
	t0 = *e.e2.Mul(&x.A0, &y.A0) // t0 = x.A0 * y.A0
	t1 = *e.e2.Mul(&x.A1, &y.A1) // t1 = x.A1 * y.A1
	t2 = *e.e2.Mul(&x.A2, &y.A2) // t2 = x.A2 * y.A2

	// Compute c0
	c0 = *e.e2.Add(&x.A1, &x.A2) // c0 = x.A1 + x.A2
	tmp = *e.e2.Add(&y.A1, &y.A2)
	c0 = *e.e2.Mul(&c0, &tmp) // c0 = (x.A1 + x.A2) * (y.A1 + y.A2)
	c0 = *e.e2.Sub(&c0, &t1)
	c0 = *e.e2.Sub(&c0, &t2)
	c0 = *e.e2.MulByNonResidue(&c0)
	c0 = *e.e2.Add(&c0, &t0)

	// Compute c1
	c1 = *e.e2.Add(&x.A0, &x.A1) // c1 = x.A0 + x.A1
	tmp = *e.e2.Add(&y.A0, &y.A1)
	c1 = *e.e2.Mul(&c1, &tmp) // c1 = (x.A0 + x.A1) * (y.A0 + y.A1)
	c1 = *e.e2.Sub(&c1, &t0)
	c1 = *e.e2.Sub(&c1, &t1)
	tmp = *e.e2.MulByNonResidue(&t2)
	c1 = *e.e2.Add(&c1, &tmp)

	// Compute c2
	tmp = *e.e2.Add(&x.A0, &x.A2) // tmp = x.A0 + x.A2
	c2 = *e.e2.Add(&y.A0, &y.A2)
	c2 = *e.e2.Mul(&c2, &tmp) // c2 = (x.A0 + x.A2) * (y.A0 + y.A2)
	c2 = *e.e2.Sub(&c2, &t0)
	c2 = *e.e2.Sub(&c2, &t2)
	c2 = *e.e2.Add(&c2, &t1)

	return &Fp6{
		A0: c0,
		A1: c1,
		A2: c2,
	}
}

func (e Ext6) Square(x *Fp6) *Fp6 {
	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf
	var c4, c5, c1, c2, c3, c0 Fp2

	// Compute intermediate values
	c4 = *e.e2.Mul(&x.A0, &x.A1) // c4 = x.A0 * x.A1
	c4 = *e.e2.Double(&c4)       // c4 = 2 * c4
	c5 = *e.e2.Square(&x.A2)     // c5 = x.A2^2
	c1 = *e.e2.MulByNonResidue(&c5)
	c1 = *e.e2.Add(&c1, &c4)     // c1 = NonResidue * c5 + c4
	c2 = *e.e2.Sub(&c4, &c5)     // c2 = c4 - c5
	c3 = *e.e2.Square(&x.A0)     // c3 = x.A0^2
	c4 = *e.e2.Sub(&x.A0, &x.A1) // c4 = x.A0 - x.A1
	c4 = *e.e2.Add(&c4, &x.A2)   // c4 = c4 + x.A2
	c5 = *e.e2.Mul(&x.A1, &x.A2) // c5 = x.A1 * x.A2
	c5 = *e.e2.Double(&c5)       // c5 = 2 * c5
	c4 = *e.e2.Square(&c4)       // c4 = c4^2
	c0 = *e.e2.MulByNonResidue(&c5)
	c0 = *e.e2.Add(&c0, &c3) // c0 = NonResidue * c5 + c3

	// Compute z.A2
	z2 := *e.e2.Add(&c2, &c4) // z.A2 = c2 + c4
	z2 = *e.e2.Add(&z2, &c5)  // z.A2 = z.A2 + c5
	z2 = *e.e2.Sub(&z2, &c3)  // z.A2 = z.A2 - c3

	// Set z.A0 and z.A1
	z0 := c0 // z.A0 = c0
	z1 := c1 // z.A1 = c1

	// Return the result
	return &Fp6{
		A0: z0,
		A1: z1,
		A2: z2,
	}
}

func (e Ext6) Inverse(x *Fp6) *Fp6 {
	var t0, t1, t2, t3, t4, t5, t6, c0, c1, c2, d1, d2 Fp2

	// Compute intermediate values
	t0 = *e.e2.Square(&x.A0)     // t0 = x.A0^2
	t1 = *e.e2.Square(&x.A1)     // t1 = x.A1^2
	t2 = *e.e2.Square(&x.A2)     // t2 = x.A2^2
	t3 = *e.e2.Mul(&x.A0, &x.A1) // t3 = x.A0 * x.A1
	t4 = *e.e2.Mul(&x.A0, &x.A2) // t4 = x.A0 * x.A2
	t5 = *e.e2.Mul(&x.A1, &x.A2) // t5 = x.A1 * x.A2

	// Compute c0
	c0 = *e.e2.MulByNonResidue(&t5) // c0 = t5 * NonResidue
	c0 = *e.e2.Neg(&c0)             // c0 = -c0
	c0 = *e.e2.Add(&c0, &t0)        // c0 = c0 + t0

	// Compute c1
	c1 = *e.e2.MulByNonResidue(&t2) // c1 = t2 * NonResidue
	c1 = *e.e2.Sub(&c1, &t3)        // c1 = c1 - t3

	// Compute c2
	c2 = *e.e2.Sub(&t1, &t4) // c2 = t1 - t4

	// Compute d1 and d2
	t6 = *e.e2.Mul(&x.A0, &c0)      // t6 = x.A0 * c0
	d1 = *e.e2.Mul(&x.A2, &c1)      // d1 = x.A2 * c1
	d2 = *e.e2.Mul(&x.A1, &c2)      // d2 = x.A1 * c2
	d1 = *e.e2.Add(&d1, &d2)        // d1 = d1 + d2
	d1 = *e.e2.MulByNonResidue(&d1) // d1 = d1 * NonResidue
	t6 = *e.e2.Add(&t6, &d1)        // t6 = t6 + d1

	// Compute the inverse of t6
	t6 = *e.e2.Inverse(&t6) // t6 = t6^-1

	// Compute the result
	c0 = *e.e2.Mul(&c0, &t6) // c0 = c0 * t6
	c1 = *e.e2.Mul(&c1, &t6) // c1 = c1 * t6
	c2 = *e.e2.Mul(&c2, &t6) // c2 = c2 * t6

	return &Fp6{
		A0: c0,
		A1: c1,
		A2: c2,
	}
}

func (e Ext6) MulByNonResidue(x *Fp6) *Fp6 {

	var result Fp6
	result.A0 = *e.e2.MulByNonResidue(&x.A2) // A0 = NonResidue * x.A2
	result.A1 = x.A0                         // A1 = x.A0
	result.A2 = x.A1                         // A2 = x.A1

	return &result
}

func (e Ext6) Select(condition frontend.Variable, a, b *Fp6) *Fp6 {
	// Select the components of a and b based on the condition
	z0 := e.e2.Select(condition, &b.A0, &a.A0)

	z1 := e.e2.Select(condition, &b.A1, &a.A1)

	z2 := e.e2.Select(condition, &b.A2, &a.A2)

	return &Fp6{
		A0: *z0,
		A1: *z1,
		A2: *z2,
	}
}

func (e Ext6) AssertIsEqual(x, y *Fp6) {
	e.e2.AssertIsEqual(&x.A0, &y.A0)
	e.e2.AssertIsEqual(&x.A1, &y.A1)
	e.e2.AssertIsEqual(&x.A2, &y.A2)

}
