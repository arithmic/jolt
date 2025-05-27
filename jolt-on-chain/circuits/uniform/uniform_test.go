package uniform

import (
	"encoding/json"
	"os"

	//cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"testing"
)

func TestGtMul(t *testing.T) {
	var gtMulCircuit GTMul
	gtMulConstraints, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &gtMulCircuit)
	if err != nil {
		t.Fatalf("failed to compile circuit: %v", err)
	}

	circuitJson, _ := json.MarshalIndent(gtMulConstraints, "", "  ")
	_ = os.WriteFile("r1cs.json", circuitJson, 0644)

	println("no of constraints are ", gtMulConstraints.GetNbConstraints())
	//
	//assignment := &GTMul{}
	//witness, err := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
	//
	//wit, _ := gtMulConstraints.Solve(witness)
	//_ = wit.(*cs.R1CSSolution).W
}
