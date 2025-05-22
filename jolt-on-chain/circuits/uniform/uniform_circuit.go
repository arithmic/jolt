package uniform

import (
	"github.com/arithmic/gnark/constraint"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

// TODO: any is too broad. Use something more restrictive.
type UniformCircuit[T any] interface {
	//frontend.Circuit

	Hint()

	Compile() *constraint.ConstraintSystem

	GenerateWitness(circuits []*T, r1cs *constraint.ConstraintSystem, numSteps uint32) fr.Vector
	ExtractMatrices(r1cs constraint.ConstraintSystem) ([]Constraint, int, int, int)
}
type Constraint struct {
	A map[string]string
	B map[string]string
	C map[string]string
}
