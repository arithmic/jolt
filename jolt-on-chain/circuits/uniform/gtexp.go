package uniform

import (
	"github.com/arithmic/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

type GTExp struct {
	//Out         [12]frontend.Variable `gnark:",public"`
	OutEval frontend.Variable `gnark:",public"`
	//Acc         [12]frontend.Variable // Poly of Accumulator
	AccEval     frontend.Variable     // Poly of Accumulator
	AccQuot     [11]frontend.Variable //Acc * Acc = AccQuot * Divisor + AccRem
	AccRem      [12]frontend.Variable //Acc * Acc = AccQuot * Divisor + AccRem
	AccInQuot   [11]frontend.Variable //AccRem * In = AccInQuot * Divisor + AccInRem
	AccInRem    [12]frontend.Variable //AccRem * In = AccInQuot * Divisor + AccInRem
	Bit         frontend.Variable
	inEval      fr.Element     //In(r)
	divisorEval fr.Element     //Divisor(r)
	rPowers     [13]fr.Element //Powers of r {1, r^2, .., r^12}

	//in  bn254.E12
	//acc bn254.E12
	//bit uint
	//out bn254.E12
}

func (circuit *GTExp) Define(api frontend.API) error {
	//accEval := frontend.Variable(0)
	accQuotEval := frontend.Variable(0)
	accRemEval := frontend.Variable(0)
	accInRemEval := frontend.Variable(0)
	accInQuotEval := frontend.Variable(0)
	api.Println("accQuotDiv is ")
	//TODO:- Write Eval Circuit.
	//Evaluate Acc, AccRem  at r
	for i := 0; i < 12; i++ {
		//accEval = api.Add(accEval, api.Mul(circuit.Acc[i], circuit.rPowers[i]))
		accRemEval = api.Add(accRemEval, api.Mul(circuit.AccRem[i], circuit.rPowers[i]))
		accInRemEval = api.Add(accInRemEval, api.Mul(circuit.AccInRem[i], circuit.rPowers[i]))
	}

	////Evaluate AccQuot at r
	for i := 0; i < 11; i++ {
		accQuotEval = api.Add(accQuotEval, api.Mul(circuit.AccQuot[i], circuit.rPowers[i]))
		accInQuotEval = api.Add(accInQuotEval, api.Mul(circuit.AccInQuot[i], circuit.rPowers[i]))
	}

	accQuotDiv := api.Mul(accQuotEval, circuit.divisorEval)
	accSquare := api.Mul(circuit.AccEval, circuit.AccEval)
	api.AssertIsEqual(accSquare, api.Add(accQuotDiv, accRemEval))

	accRemIn := api.Mul(accRemEval, circuit.inEval)
	accInQuotDiv := api.Mul(accInQuotEval, circuit.divisorEval)
	api.AssertIsEqual(accRemIn, api.Add(accInQuotDiv, accInRemEval))

	oneMinusBit := api.Sub(frontend.Variable(1), circuit.Bit)
	api.AssertIsEqual(frontend.Variable(0), api.Mul(circuit.Bit, oneMinusBit))
	expectedOut := api.Add(api.Mul(accInRemEval, circuit.Bit), api.Mul(accRemEval, oneMinusBit))
	api.AssertIsEqual(circuit.OutEval, expectedOut)
	//
	//select1 := make([]frontend.Variable, len(circuit.AccInRem))
	//select2 := make([]frontend.Variable, len(circuit.AccRem))
	////
	//for i := 0; i < len(circuit.AccInRem); i++ {
	//	select1[i] = api.Mul(circuit.AccInRem[i], circuit.Bit)
	//}
	//for i := 0; i < len(circuit.AccRem); i++ {
	//	select2[i] = api.Mul(circuit.AccRem[i], oneMinusBit)
	//}
	////
	//expectedOut := make([]frontend.Variable, len(select1))
	//for i := 0; i < len(select1); i++ {
	//	expectedOut[i] = api.Add(select1[i], select2[i])
	//}
	//for i := 0; i < len(select1); i++ {
	//	api.AssertIsEqual(circuit.Out[i], expectedOut[i])
	//}

	return nil
}
