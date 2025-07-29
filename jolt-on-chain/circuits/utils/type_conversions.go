package utils

import (
	"fmt"
	"math/big"

	"github.com/arithmic/gnark/frontend"
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

func FrontendVariableToFrElement(v frontend.Variable) (grumpkinFr.Element, error) {
	var result grumpkinFr.Element

	switch val := v.(type) {
	case grumpkinFr.Element:
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

func FrontendVariableToBN254FrElement(v frontend.Variable) (bn254Fr.Element, error) {
	var result bn254Fr.Element

	switch val := v.(type) {
	case bn254Fr.Element:
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

func MakeFrontendVariable(input []grumpkinFr.Element) []frontend.Variable {
	res := make([]frontend.Variable, len(input))
	for i, elem := range input {
		res[i] = frontend.Variable(elem)
	}
	return res
}

// Generic function to convert arrays of any size
func ConvertFrontendArrayToFrArray(vars []frontend.Variable) ([]grumpkinFr.Element, error) {
	result := make([]grumpkinFr.Element, len(vars))
	for i, v := range vars {
		elem, err := FrontendVariableToFrElement(v)
		if err != nil {
			return nil, fmt.Errorf("error converting variable at index %d: %w", i, err)
		}
		result[i] = elem
	}
	return result, nil
}
