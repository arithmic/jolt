package pcs

import (
	// "fmt"
	"fmt"
	"math/big"
	"testing"

	"github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/algebra/native/bn254/field_tower"
	"github.com/arithmic/jolt/jolt-on-chain/circuits/circuits/uniform_circuits"
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

	var dummyCircuit gtExpUniformCircuit

	_, ok := any(dummyCircuit).(uniform_circuits.UniformCircuit[gtExpUniformCircuit])
	if ok {
		fmt.Println("S implements I")
	} else {
		fmt.Println("S does NOT implement I")
	}
	circuits := make([]*gtExpUniformCircuit, 254)

	var ext field_tower.Ext12
	var e bn254.E12

	for i := 0; i < 254; i++ {
		bit := frBigInt.Bit(253 - i)
		circuits[i] = &gtExpUniformCircuit{
			In:  field_tower.FromE12(&a),
			Acc: *ext.One(),
			Bit: bit,
			Out: *ext.One(),

			in:  a,
			acc: *e.SetOne(),
			bit: bit,
			out: *e.SetOne(),
		}
	}

	r1cs := dummyCircuit.Compile()
	_ = dummyCircuit.GenerateWitness(circuits, r1cs, 254)
}
