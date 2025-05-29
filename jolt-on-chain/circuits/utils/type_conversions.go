package utils

import (
	bn254Fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	grumpkinFr "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
)

func grumpkinFrToBn254Fp(grumpkinFrElem grumpkinFr.Element) bn254Fr.Element {
	var bn254FrElem bn254Fr.Element

	bn254FrElem[0] = grumpkinFrElem[0]
	bn254FrElem[1] = grumpkinFrElem[1]
	bn254FrElem[2] = grumpkinFrElem[2]
	bn254FrElem[3] = grumpkinFrElem[3]

	return bn254FrElem
}
