package uniform

import (
	"fmt"
	"math/big"

	"github.com/arithmic/gnark/constraint"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type MSM struct {
	bases      [][]fr.Element
	powers     []big.Int
	rPowers    [13]fr.Element
	gtMultiMul *GTMultiMul
	gtExp      *GTExp
	out        []fr.Element
}

func (circuit *MSM) Compile() []constraint.ConstraintSystem {
	var r1cs []constraint.ConstraintSystem
	return r1cs
}

func (msm *MSM) CreateStepCircuits() []constraint.ConstraintSystem {

	gtExpR1Cs := msm.gtExp.CreateStepCircuit()
	gtmultimulR1Cs := msm.gtMultiMul.CreateStepCircuit()

	stepCircuits := []constraint.ConstraintSystem{gtExpR1Cs, gtmultimulR1Cs}
	return stepCircuits

}

func (msm *MSM) GenerateWitness(constraints []constraint.ConstraintSystem) fr.Vector {

	var witness fr.Vector
	input := make([][]fr.Element, len(msm.bases))
	msm.gtExp.rPowers = msm.rPowers
	for i := 0; i < len(msm.bases); i++ {
		msm.gtExp.base = ToTower(msm.bases[i])
		msm.gtExp.exp = msm.powers[i]
		witnessgtExpStep := msm.gtExp.GenerateWitness(constraints[0])
		witness = append(witness, witnessgtExpStep...)
		input[i] = FromE12(&msm.gtExp.gtExpStep.accTower)
	}

	msm.gtMultiMul.in = input
	msm.gtMultiMul.rPowers = msm.rPowers
	witnessgtMultiMul := msm.gtMultiMul.GenerateWitness(constraints[1])
	witness = append(witness, witnessgtMultiMul...)

	final_result, _ := convertFrontendArrayToFrArray(msm.gtMultiMul.gtMulStep.Rem[:])
	for i := 0; i < len(final_result); i++ {
		res := final_result[i].Equal(&msm.out[i])
		if !res {
			fmt.Println("Final result mismatch")
		}
	}
	return witness
}
