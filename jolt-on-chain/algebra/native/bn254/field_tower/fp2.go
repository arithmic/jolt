package field_tower

import (
	"github.com/arithmic/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	grumpkin_fr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type Fp2 struct {
	A0, A1 frontend.Variable
}

type Ext2 struct {
	api frontend.API
}

func FromE2(y *bn254.E2) Fp2 {
	return Fp2{
		A0: grumpkin_fr.Element(y.A0),
		A1: grumpkin_fr.Element(y.A1),
	}
}

func (e Ext2) Add(x, y *Fp2) *Fp2 {
	z0 := e.api.Add(x.A0, y.A0)
	z1 := e.api.Add(x.A1, y.A1)
	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) Double(x *Fp2) *Fp2 {
	z0 := e.api.Mul(x.A0, 2)
	z1 := e.api.Mul(x.A1, 2)
	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) Sub(x, y *Fp2) *Fp2 {
	z0 := e.api.Sub(x.A0, y.A0)
	z1 := e.api.Sub(x.A1, y.A1)
	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) Neg(x *Fp2) *Fp2 {
	z0 := e.api.Neg(x.A0)
	z1 := e.api.Neg(x.A1)
	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) Conjugate(x *Fp2) *Fp2 {
	z0 := x.A0
	z1 := e.api.Neg(x.A1)
	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) Mul(x, y *Fp2) *Fp2 {
	// var a, b, c frontend.Variable

	// Compute a = x.A0 + x.A1
	a := e.api.Add(x.A0, x.A1)

	// Compute b = y.A0 + y.A1
	b := e.api.Add(y.A0, y.A1)

	// Compute a_temp = a * b
	a_temp := e.api.Mul(a, b)

	// Compute b_temp = x.A0 * y.A0
	b_temp := e.api.Mul(x.A0, y.A0)

	// Compute c = x.A1 * y.A1
	c := e.api.Mul(x.A1, y.A1)

	// Compute z.A1 = (a_temp - b_temp) - c
	z1_temp := e.api.Sub(a_temp, b_temp)
	z1 := e.api.Sub(z1_temp, c)

	// Compute z.A0 = b_temp - c
	z0 := e.api.Sub(b_temp, c)

	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) Square(x *Fp2) *Fp2 {
	// Compute a = x.A0 + x.A1
	a := e.api.Add(x.A0, x.A1)

	// Compute b = x.A0 - x.A1
	b := e.api.Sub(x.A0, x.A1)

	// Compute a = a * b
	a = e.api.Mul(a, b)

	// Compute b = x.A0 * x.A1 * 2
	b = e.api.Mul(x.A0, x.A1)
	b = e.api.Mul(b, 2) // Double the result

	// Set z.A0 = a
	z0 := a

	// Set z.A1 = b
	z1 := b

	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) Inverse(x *Fp2) *Fp2 {
	// Compute t0 = x.A0^2
	t0 := e.api.Mul(x.A0, x.A0)

	// Compute t1 = x.A1^2
	t1 := e.api.Mul(x.A1, x.A1)

	// Compute t0 = t0 + t1
	t0 = e.api.Add(t0, t1)

	// Compute t1 = 1 / t0 (inverse of t0)
	t1 = e.api.Inverse(t0)

	// Compute z.A0 = x.A0 * t1
	z0 := e.api.Mul(x.A0, t1)

	// Compute z.A1 = -(x.A1 * t1)
	z1 := e.api.Mul(x.A1, t1)
	z1 = e.api.Neg(z1)

	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) MulByElement(x *Fp2, y *frontend.Variable) *Fp2 {
	// Compute z.A0 = x.A0 * y
	z0 := e.api.Mul(x.A0, *y)

	// Compute z.A1 = x.A1 * y
	z1 := e.api.Mul(x.A1, *y)

	return &Fp2{
		A0: z0,
		A1: z1,
	}

}

func (e Ext2) MulByNonResidue(x *Fp2) *Fp2 {
	// Compute a = 8 * x.A0 + x.A0 - x.A1
	a := e.api.Mul(x.A0, 2) // a = 2 * x.A0
	a = e.api.Mul(a, 2)     // a = 4 * x.A0
	a = e.api.Mul(a, 2)     // a = 8 * x.A0
	a = e.api.Add(a, x.A0)  // a = 8 * x.A0 + x.A0
	a = e.api.Sub(a, x.A1)  // a = 8 * x.A0 + x.A0 - x.A1

	// Compute b = 8 * x.A1 + x.A1 + x.A0
	b := e.api.Mul(x.A1, 2) // b = 2 * x.A1
	b = e.api.Mul(b, 2)     // b = 4 * x.A1
	b = e.api.Mul(b, 2)     // b = 8 * x.A1
	b = e.api.Add(b, x.A1)  // b = 8 * x.A1 + x.A1
	b = e.api.Add(b, x.A0)  // b = 8 * x.A1 + x.A1 + x.A0

	// Set z.A0 = a and z.A1 = b
	z0 := a
	z1 := b

	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) Exp(x *Fp2, k *frontend.Variable) *Fp2 {

	const n = 254
	bits := e.api.ToBinary(*k, n)

	// Initialize z identity element in Fp2
	z := &Fp2{
		A0: frontend.Variable(1),
		A1: frontend.Variable(0),
	}

	// Perform binary exponentiation
	for i := n - 1; i >= 0; i-- {
		// Square z
		z = e.Square(z)
		// Conditionally multiply z by x if the current bit is 1
		z = e.ConditionalMul(z, x, bits[i])
	}

	return z
}

func (e Ext2) ConditionalMul(a, b *Fp2, condition frontend.Variable) *Fp2 {
	// Conditionally select the real part
	z0 := e.api.Select(condition, e.Mul(a, b).A0, a.A0)

	// Conditionally select the imaginary part
	z1 := e.api.Select(condition, e.Mul(a, b).A1, a.A1)

	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) Select(condition frontend.Variable, a, b *Fp2) *Fp2 {
	// Conditionally select the real part
	z0 := e.api.Select(condition, b.A0, a.A0)

	// Conditionally select the imaginary part
	z1 := e.api.Select(condition, b.A1, a.A1)

	return &Fp2{
		A0: z0,
		A1: z1,
	}
}

func (e Ext2) AssertIsEqual(x, y *Fp2) {
	e.api.AssertIsEqual(x.A0, y.A0)
	e.api.AssertIsEqual(x.A1, y.A1)
}
