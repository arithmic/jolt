package pcs

//
//func TestGtExpUniformCircuit(t *testing.T) {
//	var a bn254.E12
//	var b bn254Fp.Element
//	_, _ = a.SetRandom()
//	_, _ = b.SetRandom()
//	var frBigInt big.Int
//	b.BigInt(&frBigInt)
//
//	circuit := gtExpUniformCircuit{
//		g:   a,
//		exp: b,
//
//		dummyCircuit: &gtExpStepCircuit{},
//	}
//
//	var _ uniform.UniformCircuit = &gtExpUniformCircuit{}
//
//	circuit.CreateStepCircuits()
//
//	// r1cs := circuit.Compile()
//
//	_ = circuit.GenerateWitness()
//
//	actualResult := field_tower.FromE12(a.Exp(a, &frBigInt))
//
//	computedResult := circuit.gtExpSteps[253].Out
//
//	fmt.Println("The auctal result is ", actualResult)
//
//	fmt.Println("The computed result is ", computedResult)
//}
