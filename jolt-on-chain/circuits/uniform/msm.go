package uniform

import (
	"github.com/arithmic/gnark/constraint"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type MSM struct {
	bases   [][]fr.Element
	powers  []fr.Element
	rPowers []fr.Element
}

func (circuit *MSM) Compile() []constraint.ConstraintSystem {
	var r1cs []constraint.ConstraintSystem
	return r1cs
}
