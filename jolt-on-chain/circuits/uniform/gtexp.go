package uniform

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/arithmic/gnark/constraint"
	cs "github.com/arithmic/gnark/constraint/grumpkin"
	"github.com/arithmic/gnark/frontend"
	"github.com/arithmic/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

func makeFrontendVariable(input []fr.Element) []frontend.Variable {
	res := make([]frontend.Variable, len(input))
	for i, elem := range input {
		res[i] = frontend.Variable(elem)
	}
	return res
}

// frontendVariableToFrElement converts a single frontend.Variable to fr.Element
func frontendVariableToFrElement(v frontend.Variable) (fr.Element, error) {
	var result fr.Element

	switch val := v.(type) {
	case fr.Element:
		result = val
	case *big.Int:
		result.SetBigInt(val)
	case big.Int:
		result.SetBigInt(&val)
	case int:
		result.SetInt64(int64(val))
	case int64:
		result.SetInt64(val)
	case uint64:
		result.SetUint64(val)
	case string:
		bigInt := new(big.Int)
		if _, ok := bigInt.SetString(val, 10); !ok {
			return result, fmt.Errorf("failed to parse string %s as big integer", val)
		}
		result.SetBigInt(bigInt)
	default:
		str := fmt.Sprintf("%v", val)
		bigInt := new(big.Int)
		if _, ok := bigInt.SetString(str, 10); !ok {
			return result, fmt.Errorf("unsupported frontend.Variable type: %T", val)
		}
		result.SetBigInt(bigInt)
	}

	return result, nil
}

// Generic function to convert arrays of any size
func convertFrontendArrayToFrArray(vars []frontend.Variable) ([]fr.Element, error) {
	result := make([]fr.Element, len(vars))
	for i, v := range vars {
		elem, err := frontendVariableToFrElement(v)
		if err != nil {
			return nil, fmt.Errorf("error converting variable at index %d: %w", i, err)
		}
		result[i] = elem
	}
	return result, nil
}

type GTExpStep struct {
	AccEval     frontend.Variable
	AccQuot     [11]frontend.Variable
	AccRem      [12]frontend.Variable
	AccInQuot   [11]frontend.Variable
	AccInRem    [12]frontend.Variable
	Bit         frontend.Variable
	AccBit      frontend.Variable
	BitOut      frontend.Variable
	OutEval     frontend.Variable
	InEval      frontend.Variable
	rPowers     [13]fr.Element
	divisorEval fr.Element

	// Native computation fields
	inTower       bn254.E12
	accTower      bn254.E12
	in            []fr.Element
	bit           uint
	bitAcc        big.Int
	reduciblePoly []fr.Element
}

func (circuit *GTExpStep) Define(api frontend.API) error {
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
	accRemIn := api.Mul(accRemEval, circuit.InEval)
	accInQuotDiv := api.Mul(accInQuotEval, circuit.divisorEval)
	api.AssertIsEqual(accRemIn, api.Add(accInQuotDiv, accInRemEval))

	api.AssertIsBoolean(circuit.Bit)
	actualOut := api.Add(api.Mul(api.Sub(accInRemEval, accRemEval), circuit.Bit), accRemEval)
	api.AssertIsEqual(circuit.OutEval, actualOut)

	bitDouble := api.Add(circuit.AccBit, circuit.AccBit)
	api.AssertIsEqual(circuit.BitOut, api.Add(bitDouble, circuit.Bit))
	return nil
}

func (circuit *GTExpStep) Hint() {
	var square bn254.E12
	square.Square(&circuit.accTower)

	var bitAccDouble big.Int
	var bitOut big.Int
	bitAccDouble.Add(&circuit.bitAcc, &circuit.bitAcc)
	bitOut.Add(&bitAccDouble, big.NewInt(int64(circuit.bit)))

	var outTower bn254.E12
	if circuit.bit == 1 {
		outTower.Mul(&square, &circuit.inTower)
	} else {
		outTower = square
	}
	acc := FromE12(&circuit.accTower)
	out := FromE12(&outTower)
	accEval := evaluateE12AtR(acc, circuit.rPowers)

	outEval := evaluateE12AtR(out, circuit.rPowers)

	//var accSquareTower bn254.E12
	accRem := FromE12(&square)

	// Compute accTower² polynomial
	accSquarePoly := multiplyPolynomials(acc, acc)
	accInPoly := multiplyPolynomials(accRem, circuit.in)

	var accInRemTower bn254.E12
	accInRemTower.Mul(&square, &circuit.inTower)
	accInRem := FromE12(&accInRemTower)

	accQuot := computeQuotientPoly(accSquarePoly, circuit.reduciblePoly, accRem)
	accInQuot := computeQuotientPoly(accInPoly, circuit.reduciblePoly, accInRem)
	var accBitCopy big.Int
	accBitCopy.Set(&circuit.bitAcc)
	circuit.AccEval = accEval
	circuit.AccQuot = [11]frontend.Variable(makeFrontendVariable(accQuot))
	circuit.AccRem = [12]frontend.Variable(makeFrontendVariable(accRem))
	circuit.AccInQuot = [11]frontend.Variable(makeFrontendVariable(accInQuot))
	circuit.AccInRem = [12]frontend.Variable(makeFrontendVariable(accInRem))
	circuit.AccBit = accBitCopy
	circuit.OutEval = outEval
	circuit.BitOut = bitOut

	circuit.accTower.Set(&outTower)
	circuit.bitAcc.Set(&bitOut)

}

func (circuit *GTExpStep) GenerateWitness(constraints constraint.ConstraintSystem) fr.Vector {
	w, err := frontend.NewWitness(circuit, ecc.GRUMPKIN.ScalarField())

	if err != nil {
		fmt.Println("Failed to create witness object", err)
	}
	wit, err := constraints.Solve(w)
	if err != nil {
		fmt.Println("Witness generation failed ", err)
	}
	wSolved := wit.(*cs.R1CSSolution).W

	return wSolved
}

type GTExp struct {
	base      bn254.E12
	exp       big.Int
	rPowers   [13]fr.Element
	gtExpStep *GTExpStep
}

func (gtExp *GTExp) CreateStepCircuit() constraint.ConstraintSystem {
	reduciblePoly := make([]fr.Element, 13)
	reduciblePoly[0].SetInt64(82)
	reduciblePoly[6].SetInt64(-18)
	reduciblePoly[12].SetOne()
	divisorEval := fr.Element{}

	for i := 0; i < len(reduciblePoly); i++ {
		var temp fr.Element
		temp.Mul(&reduciblePoly[i], &gtExp.rPowers[i])
		divisorEval.Add(&divisorEval, &temp)
	}

	gtExp.gtExpStep = &GTExpStep{
		divisorEval:   divisorEval,
		rPowers:       gtExp.rPowers,
		reduciblePoly: reduciblePoly,
	}
	gtExpConstraints, _ := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, gtExp.gtExpStep)

	return gtExpConstraints
}

func (gtExp *GTExp) GenerateWitness(constraints constraint.ConstraintSystem) fr.Vector {
	in := FromE12(&gtExp.base)
	inEval := fr.Element{}
	for i := 0; i < len(in); i++ {
		var temp fr.Element
		temp.Mul(&in[i], &gtExp.rPowers[i])
		inEval.Add(&inEval, &temp)
	}
	var e12OneTower bn254.E12
	e12OneTower.SetOne()

	gtExp.gtExpStep.InEval = inEval
	gtExp.gtExpStep.in = in
	gtExp.gtExpStep.inTower = gtExp.base

	gtExp.gtExpStep.accTower.Set(&e12OneTower)
	gtExp.gtExpStep.bitAcc.Set(&big.Int{})
	var witness fr.Vector
	for i := 0; i < 254; i++ {
		bit := gtExp.exp.Bit(253 - i)
		gtExp.gtExpStep.bit = bit

		gtExp.gtExpStep.Hint()

		gtExp.gtExpStep.Bit = bit
		witnessStep := gtExp.gtExpStep.GenerateWitness(constraints)

		for _, elem := range witnessStep {
			witness = append(witness, elem)
		}
	}

	return witness
}

func (_ *GTExpStep) ExtractMatrices(circuitR1CS constraint.ConstraintSystem) ([]Constraint, int, int, int) {
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
