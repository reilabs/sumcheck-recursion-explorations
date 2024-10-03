package main

import (
	"math/big"
	"tutorial/sumcheck-verifier-circuit/hashmanager"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"golang.org/x/exp/rand"
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
const NUMBER_OF_COEFFS_IN_QUADRATIC = 3
const NUMBER_OF_COEFFS_IN_CUBIC = 4

var ONE_HALF_CONSTANT *big.Int

func Init() {
	var success bool
	ONE_HALF_CONSTANT, success = new(big.Int).SetString("10944121435919637611123202872628637544274182200208017171849102093287904247809", 10)
	if !success {
		println("Error: Failed to set big.Int value")
	}
}

func (circuit *Circuit) Define(api frontend.API) error {
	var manager = hashmanager.NewHashManager(api)
	g_length := len(circuit.GPolynomials)
	api.AssertIsEqual(g_length, len(circuit.ChallengeVector))
	e := circuit.ExpectedSum
	for i := 0; i < g_length; i++ {
		// api.AssertIsEqual(len(circuit.GPolynomials[i]), NUMBER_OF_COEFFS_IN_LINEAR)
		api.AssertIsEqual(len(circuit.GPolynomials[i]), NUMBER_OF_COEFFS_IN_CUBIC)

		// Equivavent constraint to the one below it, doesn't require GPoly[i][0]
		// e = api.Add(api.Mul(ONE_HALF_CONSTANT, api.Add(e, api.Neg(circuit.GPolynomials[i][1]))), api.Mul(circuit.ChallengeVector[i], circuit.GPolynomials[i][1]))
		// println("hash preimage: ", circuit.GPolynomials[i][0])
		api.Println(circuit.GPolynomials[i][0])
		hashUntilNow := manager.WriteInputAndCollectAndReturnHash(circuit.GPolynomials[i][0])
		api.Println(hashUntilNow)
		cumulative := circuit.GPolynomials[i][NUMBER_OF_COEFFS_IN_CUBIC-1]
		for j := NUMBER_OF_COEFFS_IN_CUBIC - 2; j >= 1; j-- {
			cumulative = api.Add(circuit.GPolynomials[i][j], api.Mul(cumulative, circuit.ChallengeVector[i]))
		}
		e = api.Add(circuit.GPolynomials[i][0], api.Mul(cumulative, circuit.ChallengeVector[i]))
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

	// START Basic case
	// var number_of_variables = 3

	// // initialize coefficients
	// var coeffs_univariate_polynomials = make([][]frontend.Variable, number_of_variables)
	// for i := 0; i < number_of_variables; i++ {
	// 	coeffs_univariate_polynomials[i] = make([]frontend.Variable, NUMBER_OF_COEFFS_IN_LINEAR)
	// }
	// var challenge_vec = make([]frontend.Variable, number_of_variables)
	// var circuit = Circuit{
	// 	GPolynomials:    coeffs_univariate_polynomials,
	// 	ChallengeVector: challenge_vec,
	// }

	// ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	// pk, vk, _ := groth16.Setup(ccs)

	// // f(x, y, z) = xy + yz + 2x + 3z
	// // polynomials are represented by their evals at {0,1}^3, ordered sequentially, (0,1,1) -> 4

	// var f = []int{0, 3, 0, 4, 2, 5, 3, 7}

	// var initial_expected_sum = sumArray(f)
	// var expected_sum = sumArray(f)
	// var challenge_vector []frontend.Variable

	// println(expected_sum)

	// for i := 0; i < number_of_variables; i++ {
	// 	p_0 := sumArray(f[:len(f)/2])
	// 	p_1 := expected_sum - p_0 - p_0
	// 	coeffs_univariate_polynomials[i] = []frontend.Variable{p_0, p_1}
	// 	r := rand.Intn(11)
	// 	println("r_", i, " = ", r)
	// 	challenge_vector = append(challenge_vector, r)
	// 	f = replace_r_in_f(f, r)
	// 	expected_sum = p_0 + r*p_1
	// }

	// assignment := Circuit{
	// 	ExpectedSum:            initial_expected_sum,
	// 	ValueAtChallengeVector: expected_sum,
	// 	GPolynomials:           coeffs_univariate_polynomials,
	// 	ChallengeVector:        challenge_vector,
	// }
	// witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	// publicWitness, _ := witness.Public()
	// proof, _ := groth16.Prove(ccs, pk, witness)
	// groth16.Verify(proof, vk, publicWitness)

	// END Basic case

	// START A bit more advanced case
	// Sum_x f(x) * g(x)

	// var number_of_variables = 2

	// // initialize coefficients
	// var coeffs_univariate_polynomials = make([][]frontend.Variable, number_of_variables)
	// for i := 0; i < number_of_variables; i++ {
	// 	coeffs_univariate_polynomials[i] = make([]frontend.Variable, NUMBER_OF_COEFFS_IN_QUADRATIC)
	// }
	// var challenge_vec = make([]frontend.Variable, number_of_variables)
	// var circuit = Circuit{
	// 	GPolynomials:    coeffs_univariate_polynomials,
	// 	ChallengeVector: challenge_vec,
	// }

	// ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	// pk, vk, _ := groth16.Setup(ccs)

	// // f(x, y) = 2x + 3y + 1
	// // g(x, y) = x + xy + 2y
	// // polynomials are represented by their evals at {0,1}^2, ordered sequentially, (0,1) -> 4*2 = 8

	// var f = []int{1, 4, 3, 6}
	// var g = []int{0, 2, 1, 4}
	// var f_g = []int{0, 8, 3, 24}
	// var initial_expected_sum = sumArray(f_g)
	// var expected_sum = initial_expected_sum
	// var challenge_vector []frontend.Variable

	// println(expected_sum)

	// for i := 0; i < number_of_variables; i++ {
	// 	p_0 := 0
	// 	p_2 := 0
	// 	for j := 0; j < len(f)/2; j++ {
	// 		p_0 += f[j] * g[j]
	// 		p_2 += (f[j+(len(f)/2)] - f[j]) * (g[j+(len(g)/2)] - g[j])
	// 	}

	// 	p_1 := expected_sum - p_0 - p_0 - p_2
	// 	coeffs_univariate_polynomials[i] = []frontend.Variable{p_0, p_1, p_2}
	// 	r := rand.Intn(11)
	// 	println("r_", i, " = ", r)
	// 	challenge_vector = append(challenge_vector, r)
	// 	f = replace_r_in_f(f, r)
	// 	g = replace_r_in_f(g, r)
	// 	expected_sum = p_0 + r*(p_1+r*p_2)
	// }

	// assignment := Circuit{
	// 	ExpectedSum:            initial_expected_sum,
	// 	ValueAtChallengeVector: expected_sum,
	// 	GPolynomials:           coeffs_univariate_polynomials,
	// 	ChallengeVector:        challenge_vector,
	// }
	// witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	// publicWitness, _ := witness.Public()
	// proof, _ := groth16.Prove(ccs, pk, witness)
	// groth16.Verify(proof, vk, publicWitness)
	// END A bit more advanced case

	// START R1CS case
	// Sum_x e(x) * (a(x) * b(x) - c(x))
	var number_of_variables = 2

	// initialize coefficients
	var coeffs_univariate_polynomials = make([][]frontend.Variable, number_of_variables)
	for i := 0; i < number_of_variables; i++ {
		coeffs_univariate_polynomials[i] = make([]frontend.Variable, NUMBER_OF_COEFFS_IN_CUBIC)
	}
	var challenge_vec = make([]frontend.Variable, number_of_variables)
	var circuit = Circuit{
		GPolynomials:    coeffs_univariate_polynomials,
		ChallengeVector: challenge_vec,
	}

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(ccs)
	// proof for some random values of e, Az, Bz, Cz
	// still to validate for real A,B,C and its witness vector

	VerifyR1CS()

	var e = []int{1, 4, 3, 6, 3, 5}

	var a_z = []int{3, 9, 30, 25, 5, 25}
	var b_z = []int{3, 3, 1, 1, 5, 1}
	var c_z = []int{9, 27, 30, 25, 25, 25}
	var final = []int{0, 324, 180, 750, 150, 500}
	var initial_expected_sum = sumArray(final)
	var expected_sum = initial_expected_sum
	var challenge_vector []frontend.Variable

	println(expected_sum)

	for i := 0; i < number_of_variables; i++ {
		p_0 := 0
		p_tmp := 0
		p_3 := 0
		offset := len(e) / 2
		for j := 0; j < len(e)/2; j++ {
			p_0 += e[j] * (a_z[j]*a_z[j] - a_z[j])
			p_tmp += (2*e[j] - e[j+offset]) * ((2*a_z[j]-a_z[j+offset])*(2*b_z[j]-b_z[j+offset]) - (2*c_z[j] - c_z[j+offset]))
			p_3 += (e[j+offset] - e[j]) * (a_z[j+offset] - a_z[j]) * (b_z[j+offset] - b_z[j])
		}
		p_2 := (expected_sum + p_tmp - p_0 - p_0 - p_0) / 2
		p_1 := expected_sum - p_0 - p_0 - p_3 - p_2
		println("P_0 = ", p_0)
		coeffs_univariate_polynomials[i] = []frontend.Variable{p_0, p_1, p_2, p_3}
		// println("============")
		println(poseidon.Hash([]*big.Int{}))
		r := rand.Intn(11)
		println("r_", i, " = ", r)
		challenge_vector = append(challenge_vector, r)
		e = replace_r_in_f(e, r)
		a_z = replace_r_in_f(a_z, r)
		b_z = replace_r_in_f(b_z, r)
		c_z = replace_r_in_f(c_z, r)
		expected_sum = p_0 + r*(p_1+r*(p_2+r*p_3))
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
	//END R1CS case
}
