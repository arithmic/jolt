package uniform

import (
	"github.com/arithmic/gnark/constraint"
	"github.com/arithmic/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type StepCircuit interface {
	frontend.Circuit

	Hint()
	GenerateWitness(constraints constraint.ConstraintSystem) fr.Vector
}

type UniformCircuit interface {
	CreateStepCircuit() constraint.ConstraintSystem

	GenerateWitness(constraints constraint.ConstraintSystem) fr.Vector

	//GetConstraints() UniformR1CS

	// ExtractMatrices() ([]Constraint, int, int, int)
}

type PiecewiseUniformCircuit interface {
	// Compile TODO: Maybe not needed. Remove.
	Compile() *[]constraint.ConstraintSystem

	CreateStepCircuits()

	GenerateWitness() fr.Vector

	GetConstraints() PiecewiseUniformR1CS

	// ExtractMatrices() ([]Constraint, int, int, int)
}

type PiecewiseUniformR1CS struct {
	UniformR1CSes []UniformR1CS
}

type UniformR1CS struct {
	Constraints []Constraint

	ACount   uint32
	BCount   uint32
	CCount   uint32
	NumSteps uint32
}

type Constraint struct {
	A map[string]string
	B map[string]string
	C map[string]string
}
