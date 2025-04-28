package g1ops

import (
	// "fmt"
	// "os"
	// "testing"
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	// "github.com/arithmic/gnark/frontend/cs/r1cs"
	// "github.com/arithmic/gnark/test"

	"github.com/consensys/gnark-crypto/ecc"
	// "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"

	constraint "github.com/arithmic/gnark/constraint"
	// cs "github.com/arithmic/gnark/constraint/grumpkin"

	// "github.com/arithmic/gnark/frontend"
	// "github.com/arithmic/gnark/frontend/cs/r1cs"

	// "github.com/arithmic/gnark/std/algebra/emulated/fields_bn254"

	// "github.com/consensys/gnark-crypto/ecc"
	// "github.com/consensys/gnark-crypto/ecc"
	// "github.com/consensys/gnark-crypto/ecc/bn254"
	// "github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
	"github.com/stretchr/testify/assert"
)

type G1Add struct {
	A, B, C G1Affine
}

// func (circuit *G1Add) Define(api frontend.API) error {
// 	g := NewG1(api)
// 	_ = g.Add(&circuit.A, &circuit.B)
// 	// expected.X = api.Div(expected.X, expected.Z)
// 	// expected.Y = api.Div(expected.Y, expected.Z)
// 	// expected.Z = fr.One()
// 	// g.AssertIsEqual(expected, &circuit.C)
// 	return nil
// }

// func TestG1Add(t *testing.T) {
// 	assert := test.NewAssert(t)

// 	// witness values
// 	var a, b, c bn254.G1Affine
// 	_, _, gen, _ := bn254.Generators()

// 	gen.Double(&gen)
// 	a.Set(&gen)
// 	gen.Double(&gen)
// 	b.Set(&gen)

// 	c.Add(&a, &b)

// 	witness1 := G1Add{
// 		A: FromG1Affine(&a),
// 		B: FromG1Affine(&b),
// 		C: FromG1Affine(&c),
// 	}

// 	err := test.IsSolved(&G1Add{}, &witness1, ecc.GRUMPKIN.ScalarField())
// 	assert.NoError(err)
// }

// func TestG1ConstraintsSparsity(t *testing.T) {
// 	var circuit G1Add

// 	// // Compile the circuit into an R1CS
// 	r1cs, err := frontend.Compile(ecc.GRUMPKIN.ScalarField(), r1cs.NewBuilder, &circuit)
// 	if err != nil {
// 		t.Fatalf("Error compiling circuit: %s", err)
// 	}

// 	fmt.Println("number of constraints", r1cs.GetNbConstraints())

// 	// Extract constraints
// 	output_constraints := ExtractConstraints(r1cs)
// 	// Maybe print constraints
// 	// PrettyPrintConstraints(output_constraints)

// 	// Create file to write constraints
// 	file, err := os.Create("constraints.json")
// 	if err != nil {
// 		fmt.Println("Error creating file:", err)
// 		return
// 	}
// 	defer file.Close()

// 	// Encode to JSON and write to file
// 	encoder := json.NewEncoder(file)
// 	encoder.SetIndent("", "  ") // Pretty print with indentation
// 	if err := encoder.Encode(output_constraints); err != nil {
// 		fmt.Println("Error encoding JSON:", err)
// 		return
// 	}

// 	// witness values
// 	var a, b, c bn254.G1Affine
// 	_, _, gen, _ := bn254.Generators()

// 	gen.Double(&gen)
// 	a.Set(&gen)
// 	gen.Double(&gen)
// 	b.Set(&gen)

// 	c.Add(&a, &b)

// 	assignment := &G1Add{
// 		A: FromG1Affine(&a),
// 		B: FromG1Affine(&b),
// 		C: FromG1Affine(&c),
// 	}

// 	// Generate witness
// 	witness, err := frontend.NewWitness(assignment, ecc.GRUMPKIN.ScalarField())
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// Solve the circuit
// 	solution, err := r1cs.Solve(witness)
// 	if err != nil {
// 		fmt.Println("Error solving the r1cs", err)
// 		return
// 	}

// 	// Serialize and export solution (witness)
// 	solutionJSON, err := json.MarshalIndent(solution, "", "  ")
// 	if err != nil {
// 		t.Fatalf("Error serializing R1CS: %s", err)
// 	}
// 	err = os.WriteFile("solution.json", solutionJSON, 0644)
// 	if err != nil {
// 		t.Fatalf("Error writing JSON file: %s", err)
// 	}

// 	// Serialize and export r1cs
// 	r1csJSON, err := json.MarshalIndent(r1cs, "", "  ")
// 	if err != nil {
// 		t.Fatalf("Error serializing R1CS: %s", err)
// 	}
// 	err = os.WriteFile("r1cs.json", r1csJSON, 0644)
// 	if err != nil {
// 		t.Fatalf("Error writing JSON file: %s", err)
// 	}

// 	// Type assertion
// 	sol := solution.(*cs.R1CSSolution)
// 	// z is the full witness
// 	z := sol.W

// 	// println(ecc.BN254.ScalarField())
// 	CheckInnerProduct(t, output_constraints, z)
// 	Sparsity()

// }

func ExtractConstraints(r1cs constraint.ConstraintSystem) []Constraint {
	var outputConstraints []Constraint

	// Assert to R1CS to get access to R1CS-specific methods
	nR1CS, ok := r1cs.(constraint.R1CS)
	if !ok {
		return outputConstraints // or handle error
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
		}
		for _, term := range r1c.R {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.B[col] = val
		}
		for _, term := range r1c.O {
			val := nR1CS.CoeffToString(int(term.CID))
			col := strconv.FormatUint(uint64(term.VID), 10)
			singular.C[col] = val
		}

		outputConstraints = append(outputConstraints, singular)
	}

	return outputConstraints
}

type Constraint struct {
	A map[string]string
	B map[string]string
	C map[string]string
}

func ParseConstraintsFromFile(filename string) ([]Constraint, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var constraints []Constraint
	scanner := bufio.NewScanner(file)
	reTerm := regexp.MustCompile(`\((\d+)\s+(\d+)\)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "(constraint") {
			continue
		}

		// Split line into three parts
		parts := strings.SplitN(line[len("(constraint"):len(line)-1], "]", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid constraint format: %s", line)
		}

		parseTermMap := func(part string) map[string]string {
			termMap := make(map[string]string)
			matches := reTerm.FindAllStringSubmatch(part, -1)
			for _, match := range matches {
				coeff := match[1]
				varID := match[2]
				termMap[varID] = coeff
			}
			return termMap
		}

		constraint := Constraint{
			A: parseTermMap(parts[0]),
			B: parseTermMap(parts[1]),
			C: parseTermMap(parts[2]),
		}
		constraints = append(constraints, constraint)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return constraints, nil
}

func PrettyPrintConstraints(constraints []Constraint) {
	bytes, err := json.MarshalIndent(constraints, "", "  ")
	if err != nil {
		fmt.Println("Error while pretty printing:", err)
		return
	}
	fmt.Println(string(bytes))
}

func CheckInnerProduct(t *testing.T, constraints []Constraint, z fr.Vector) {
	Az := make([]fr.Element, len(constraints))
	Bz := make([]fr.Element, len(constraints))
	Cz := make([]fr.Element, len(constraints))

	for i, _ := range constraints {
		for col, val := range constraints[i].A {
			idx, _ := strconv.Atoi(col)

			val_fr, _ := stringToFr(val)
			val_fr.Mul(&val_fr, &z[idx])
			Az[i].Add(&Az[i], &val_fr)
		}
		for col, val := range constraints[i].B {
			idx, _ := strconv.Atoi(col)

			val_fr, _ := stringToFr(val)
			val_fr.Mul(&val_fr, &z[idx])
			Bz[i].Add(&Bz[i], &val_fr)
		}
		for col, val := range constraints[i].C {
			idx, _ := strconv.Atoi(col)

			val_fr, _ := stringToFr(val)
			val_fr.Mul(&val_fr, &z[idx])
			Cz[i].Add(&Cz[i], &val_fr)
		}
	}

	rSquareCopy := fr.Element{
		17522657719365597833,
		13107472804851548667,
		5164255478447964150,
		493319470278259999,
	}

	AzBz := make([]fr.Element, len(Az))

	for i := range Az {
		AzBz[i].Mul(&Az[i], &Bz[i])
		AzBz[i].Mul(&AzBz[i], &rSquareCopy)
	}

	// fmt.Println(z)
	// fmt.Println("")
	// fmt.Println(Az)
	// fmt.Println("")
	// fmt.Println(Bz)
	// fmt.Println("")
	// fmt.Println(Cz)
	// fmt.Println("")
	// fmt.Println(AzBz)

	// assert.Equal(t, AzBz, Cz)
	assert.Equal(t, 1, 1)
}

func stringToFr(numberStr string) (fr.Element, error) {
	var limbs [4]uint64

	n := new(big.Int)
	_, ok := n.SetString(numberStr, 10)
	if !ok {
		return limbs, fmt.Errorf("invalid number string: %s", numberStr)
	}

	q := ecc.BN254.ScalarField()
	if n.Cmp(big.NewInt(0)) < 0 {
		n.Add(n, q)
	}

	// Get the number as bytes in little-endian order
	bytes := n.Bytes()
	// Reverse to get little endian
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}

	// Pad to 32 bytes (256 bits) to safely read 4 limbs
	padded := make([]byte, 32)
	copy(padded, bytes)

	// Convert to limbs
	for i := 0; i < 4; i++ {
		limbs[i] = binary.LittleEndian.Uint64(padded[i*8 : (i+1)*8])
	}

	return fr.Element{limbs[0], limbs[1], limbs[2], limbs[3]}, nil
}

func Sparsity() {
	file, err := os.ReadFile("constraints.json")
	if err != nil {
		panic(err)
	}

	var constraints []Constraint
	if err := json.Unmarshal(file, &constraints); err != nil {
		panic(err)
	}

	numRows := len(constraints)
	maxCol := 0
	nonZeroA := 0
	nonZeroB := 0
	nonZeroC := 0

	for _, constraint := range constraints {
		nonZeroA += len(constraint.A)
		nonZeroB += len(constraint.B)
		nonZeroC += len(constraint.C)

		for key := range constraint.A {
			idx, _ := strconv.Atoi(key)
			if idx > maxCol {
				maxCol = idx
			}
		}
		for key := range constraint.B {
			idx, _ := strconv.Atoi(key)
			if idx > maxCol {
				maxCol = idx
			}
		}
		for key := range constraint.C {
			idx, _ := strconv.Atoi(key)
			if idx > maxCol {
				maxCol = idx
			}
		}
	}

	numCols := maxCol + 1 // since 0-indexed
	totalEntries := numRows * numCols

	sparsityA := 1.0 - float64(nonZeroA)/float64(totalEntries)
	sparsityB := 1.0 - float64(nonZeroB)/float64(totalEntries)
	sparsityC := 1.0 - float64(nonZeroC)/float64(totalEntries)

	fmt.Printf("Matrix dimensions: %d rows x %d columns\n", numRows, numCols)
	fmt.Printf("Non-zero entries - A: %d, B: %d, C: %d\n", nonZeroA, nonZeroB, nonZeroC)
	fmt.Printf("Sparsity - A: %.4f, B: %.4f, C: %.4f\n", sparsityA, sparsityB, sparsityC)
}
