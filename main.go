package main

import (
	"math/big"
	"math/rand"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type Circuit struct {
	// Alleged computed sum of all the evaluations
	ExpectedSum            frontend.Variable   `gnark:"ExpectedSum"`
	ValueAtChallengeVector frontend.Variable   `gnark:"ValueAtChallengeVector"`
	ChallengeVector        []frontend.Variable `gnark:"ChallengeVector"`
	// Array of elements representing the values of p0, p1 in each of the rounds
	GPolynomials [][]frontend.Variable `gnark:"GPolynomials"`
}

const NUMBER_OF_COEFFS_IN_LINEAR = 2

var ONE_HALF_CONSTANT *big.Int

func Init() {
	var success bool
	ONE_HALF_CONSTANT, success = new(big.Int).SetString("10944121435919637611123202872628637544274182200208017171849102093287904247809", 10)
	if !success {
		println("Error: Failed to set big.Int value")
	}
}

func (circuit *Circuit) Define(api frontend.API) error {
	// var manager = hashmanager.NewHashManager(api)
	api.AssertIsEqual(circuit.ExpectedSum, api.Add(circuit.GPolynomials[0][0], api.Add(circuit.GPolynomials[0][0], circuit.GPolynomials[0][1])))
	g_length := len(circuit.GPolynomials)
	api.AssertIsEqual(g_length, len(circuit.ChallengeVector))
	e := circuit.ExpectedSum
	for i := 0; i < g_length; i++ {
		api.AssertIsEqual(len(circuit.GPolynomials[i]), NUMBER_OF_COEFFS_IN_LINEAR)
		// Equivavent constraint to the one below it, doesn't require GPoly[i][0]
		// e = api.Add(api.Mul(ONE_HALF_CONSTANT, api.Add(e, api.Neg(circuit.GPolynomials[i][1]))), api.Mul(circuit.ChallengeVector[i], circuit.GPolynomials[i][1]))
		e = api.Add(circuit.GPolynomials[i][0], api.Mul(circuit.ChallengeVector[i], circuit.GPolynomials[i][1]))
	}
	api.AssertIsEqual(e, circuit.ValueAtChallengeVector)
	return nil
}

func numOfCoeffsInMultilinearPolynomial(number_of_variables int) int {
	return 1 << number_of_variables
}

func sumArray(numbers []int) int {
	result := 0
	for i := 0; i < len(numbers); i++ {
		result += numbers[i]
	}
	return result
}

func replace_r_in_f(f []int, r int) []int {
	n := len(f) / 2
	for i := 0; i < n; i++ {
		diff := f[n+i] - f[i]
		scaled := r * diff
		f[i] += scaled
	}
	return f[:n]
}

func main() {
	Init()
	var number_of_variables = 3

	// initialize coefficients
	var coeffs_univariate_polynomials = make([][]frontend.Variable, number_of_variables)
	for i := 0; i < number_of_variables; i++ {
		coeffs_univariate_polynomials[i] = make([]frontend.Variable, NUMBER_OF_COEFFS_IN_LINEAR)
	}
	var challenge_vec = make([]frontend.Variable, number_of_variables)
	var circuit = Circuit{
		GPolynomials:    coeffs_univariate_polynomials,
		ChallengeVector: challenge_vec,
	}

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(ccs)

	// f(x, y, z) = xy + yz + 2x + 3z
	// polynomials are represented by their evals at {0,1}^3, ordered sequentially, (0,1,1) -> 4

	var f = []int{0, 3, 0, 4, 2, 5, 3, 7}

	var initial_expected_sum = sumArray(f)
	var expected_sum = sumArray(f)
	var challenge_vector []frontend.Variable

	println(expected_sum)

	for i := 0; i < number_of_variables; i++ {
		p_0 := sumArray(f[:len(f)/2])
		p_1 := expected_sum - p_0 - p_0
		coeffs_univariate_polynomials[i] = []frontend.Variable{p_0, p_1}
		r := rand.Intn(11)
		println("r_", i, " = ", r)
		challenge_vector = append(challenge_vector, r)
		f = replace_r_in_f(f, r)
		expected_sum = p_0 + r*p_1
	}

	assignment := Circuit{
		ExpectedSum:            initial_expected_sum,
		ValueAtChallengeVector: expected_sum,
		GPolynomials:           coeffs_univariate_polynomials,
		ChallengeVector:        challenge_vector,
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
