package pairing

import (

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func MillerLoop_fn(
	Q *bn254.G2Affine,
	P *bn254.G1Affine,
) *bn254.E12 {
	// Define constants
	n := 64
	bits := []int{
		0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
		0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
		-1, 0, 0, 0, 1, 0, 1,
	}

	// Compute ell_coeff using precomputation
	ellCoeff, _ := EllCoeffs_fn(Q)

	// Initialize Miller loop accumulator
	f := make([]bn254.E12, 4)
	f[0].SetOne() // f[0] = 1 in Fp12

	// Miller loop
	for i := 0; i < n; i++ {
		bit := bits[n-1-i]
		f1, f2, f3 := MillerLoopStep_fn(&f[0], ellCoeff[2*i:2*i+2], P, bit)
		f[0] = f3
		f[1] = f1
		f[2] = f2
	}

	// Final 2 steps (hardcoded)
	f[1] = *Ell_fn(&f[0], &ellCoeff[2*n], P)
	f[2] = *Ell_fn(&f[1], &ellCoeff[2*n+1], P)

	return &f[2]
}