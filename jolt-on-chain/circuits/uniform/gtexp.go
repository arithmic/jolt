package uniform

import (
	"fmt"
	"github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
	"math/big"
	"strconv"
)

func makeFrontendVariable(input []fr.Element) []frontend.Variable {
	res := make([]frontend.Variable, len(input))
	for i, elem := range input {
		res[i] = frontend.Variable(elem) // Explicit conversion if needed
	}
	return res
}

type GTExp struct {
	AccEval     frontend.Variable
	AccQuot     [11]frontend.Variable
	AccRem      [12]frontend.Variable
	AccInQuot   [11]frontend.Variable
	AccInRem    [12]frontend.Variable
	Bit         frontend.Variable
	AccBit      frontend.Variable
	OutBit      frontend.Variable
	OutEval     frontend.Variable
	inEval      fr.Element
	divisorEval fr.Element
	rPowers     [13]fr.Element

	// Native computation fields
	inTower       bn254.E12
	accTower      bn254.E12
	in            []fr.Element
	exp           big.Int
	bit           uint
	out           bn254.E12
	bitOut        big.Int
	bitAcc        big.Int
	reduciblePoly []fr.Element
}

func (circuit *GTExp) Define(api frontend.API) error {
	accQuotEval := frontend.Variable(0)
	accRemEval := frontend.Variable(0)
	accInRemEval := frontend.Variable(0)
	accInQuotEval := frontend.Variable(0)

	// Evaluate AccRem and AccInRem at r
	for i := 0; i < 12; i++ {
		accRemEval = api.Add(accRemEval, api.Mul(circuit.AccRem[i], circuit.rPowers[i]))
		accInRemEval = api.Add(accInRemEval, api.Mul(circuit.AccInRem[i], circuit.rPowers[i]))
	}

	// Evaluate AccQuot and AccInQuot at r
	for i := 0; i < 11; i++ {
		accQuotEval = api.Add(accQuotEval, api.Mul(circuit.AccQuot[i], circuit.rPowers[i]))
		accInQuotEval = api.Add(accInQuotEval, api.Mul(circuit.AccInQuot[i], circuit.rPowers[i]))
	}

	// Verify polynomial division: accTower² = accQuot * divisor + accRem
	accQuotDiv := api.Mul(accQuotEval, circuit.divisorEval)
	accSquare := api.Mul(circuit.AccEval, circuit.AccEval)
	api.AssertIsEqual(accSquare, api.Add(accQuotDiv, accRemEval))

	// Verify polynomial division: accRem * inTower = accInQuot * divisor + accInRem
	accRemIn := api.Mul(accRemEval, circuit.inEval)
	accInQuotDiv := api.Mul(accInQuotEval, circuit.divisorEval)
	api.AssertIsEqual(accRemIn, api.Add(accInQuotDiv, accInRemEval))

	api.AssertIsBoolean(circuit.Bit)
	actualOut := api.Add(api.Mul(api.Sub(accInRemEval, accRemEval), circuit.Bit), accRemEval)
	api.AssertIsEqual(circuit.OutEval, actualOut)

	bitDouble := api.Add(circuit.AccBit, circuit.AccBit)
	api.AssertIsEqual(circuit.OutBit, api.Add(bitDouble, circuit.Bit))
	return nil
}

func (circuit *GTExp) Hint() {
	var square bn254.E12
	square.Square(&circuit.accTower)

	var bitAccDouble big.Int
	bitAccDouble.Add(&circuit.bitAcc, &circuit.bitAcc)
	circuit.bitOut.Add(&bitAccDouble, big.NewInt(int64(circuit.bit)))

	if circuit.bit == 1 {
		circuit.out.Mul(&square, &circuit.inTower)
	} else {
		circuit.out = square
	}

}

func (circuit *GTExp) Compile() *constraint.ConstraintSystem {
	circuitR1CS, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("err inTower compilation is ", err)
	}
	return &circuitR1CS
}

func (circuit *GTExp) GenerateWitness(_ *GTExp, r1cs *constraint.ConstraintSystem, numCircuits int) fr.Vector {
	var witness fr.Vector
	for i := 0; i < numCircuits; i++ {
		circuit.accTower.Set(&circuit.out)
		bit := circuit.exp.Bit(253 - i)

		circuit.bit = bit
		circuit.bitAcc.Set(&circuit.bitOut)

		circuit.Hint()

		acc := FromE12(&circuit.accTower)
		out := FromE12(&circuit.out)
		accEval := evaluateE12AtR(acc, circuit.rPowers)

		outEval := evaluateE12AtR(out, circuit.rPowers)

		var accSquareTower bn254.E12
		accSquareTower.Square(&circuit.accTower)
		accRem := FromE12(&accSquareTower)

		// Compute accTower² polynomial
		accSquarePoly := multiplyPolynomials(acc, acc)
		accInPoly := multiplyPolynomials(accRem, circuit.in)
		var accInRemTower bn254.E12
		accInRemTower.Mul(&accSquareTower, &circuit.inTower)
		accInRem := FromE12(&accInRemTower)

		accQuot := computeQuotientPoly(accSquarePoly, circuit.reduciblePoly, accRem)
		accInQuot := computeQuotientPoly(accInPoly, circuit.reduciblePoly, accInRem)

		circuit.OutEval = outEval
		circuit.AccEval = accEval
		circuit.AccQuot = [11]frontend.Variable(makeFrontendVariable(accQuot))
		circuit.AccRem = [12]frontend.Variable(makeFrontendVariable(accRem))
		circuit.AccInQuot = [11]frontend.Variable(makeFrontendVariable(accInQuot))
		circuit.AccInRem = [12]frontend.Variable(makeFrontendVariable(accInRem))
		circuit.AccBit = circuit.bitAcc
		circuit.OutBit = circuit.bitOut
		circuit.Bit = bit

		w, err := frontend.NewWitness(circuit, ecc.GRUMPKIN.ScalarField())
		if err != nil {
			fmt.Println("Witness generation failed ", err)
		}
		wSolved, _ := (*r1cs).Solve(w)

		witnessStep := wSolved.(*cs.R1CSSolution).W

		for _, elem := range witnessStep {
			witness = append(witness, elem)
		}
	}

	return witness
}

func (circuit *GTExp) ExtractMatrices(circuitR1CS constraint.ConstraintSystem) ([]Constraint, int, int, int) {
	var outputConstraints []Constraint
	var aCount, bCount, cCount int

	nR1CS, ok := circuitR1CS.(constraint.R1CS)
	if !ok {
		return outputConstraints, 0, 0, 0
	}
	constraints := nR1CS.GetR1Cs()
	for _, r1c := range constraints {
		singular := Constraint{
			A: make(map[string]string),
			B: make(map[string]string),
			C: make(map[string]string),
		}

		for _, term := range r1c.L {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.A[col] = val
			aCount++
		}
		for _, term := range r1c.R {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.B[col] = val
			bCount++
		}
		for _, term := range r1c.O {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.C[col] = val
			cCount++
		}

		outputConstraints = append(outputConstraints, singular)
	}

	return outputConstraints, aCount, bCount, cCount
}

// Helper function to evaluate E12 at point r
func evaluateE12AtR(coeffs []fr.Element, rPowers [13]fr.Element) fr.Element {
	var result fr.Element
	for i := 0; i < 12; i++ {
		var temp fr.Element
		temp.Mul(&coeffs[i], &rPowers[i])
		result.Add(&result, &temp)
	}
	return result
}
