package pcs

import (
	"fmt"
	"math/big"
	"testing"

	// "github.com/arithmic-bhargav/jolt/jolt-on-chain/circuits/uniform/uniform_circuit"

	"github.com/arithmic/jolt/jolt-on-chain/circuits/algebra/native/bn254/field_tower"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/uniform"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254Fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

func TestGtExpUniformCircuit(t *testing.T) {
	var a bn254.E12
	var b bn254Fp.Element
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	var frBigInt big.Int
	b.BigInt(&frBigInt)

	circuit := gtExpUniformCircuit{
		g:   a,
		exp: b,

		dummyCircuit: &gtExpStepCircuit{},
	}

	var _ uniform.UniformCircuit = &gtExpUniformCircuit{}

	circuit.CreateStepCircuits()

	// r1cs := circuit.Compile()

	_ = circuit.GenerateWitness()

	actualResult := field_tower.FromE12(a.Exp(a, &frBigInt))

	computedResult := circuit.gtExpSteps[253].Out

	fmt.Println("The auctal result is ", actualResult)

	fmt.Println("The computed result is ", computedResult)
}
