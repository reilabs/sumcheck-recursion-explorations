package main

import(
    "github.com/consensys/gnark/frontend/cs/r1cs"
    "github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/frontend"
    "tutorial/sumcheck-verifier-circuit/polynomials"
    "tutorial/sumcheck-verifier-circuit/hashmanager"
    "math/big"
)

type Circuit struct {
    InitialSeed frontend.Variable `gnark:"Initial Seed"` 
    // Alleged computed sum of all the evaluations 
    ComputedSum frontend.Variable `gnark:"ComputedSum"`
    // Coefficients of the multilinear polynomial whose sum is being calculated in the Sum-check protocol
    CoeffsOfInitialMultilinearPolynomial []frontend.Variable `gnark:"Initial Multilinear Polynomial Coefficients"`
    // Coefficients of the univariate polynomial used in the middle steps of the Sum-check protocol
    CoeffsOfMiddleUnivariatePolynomials [][]frontend.Variable `gnark:"Middle Univariate Polynomials Coefficients"`
}

func assertSumOfEvaluationAt0And1 (api frontend.API, result frontend.Variable, coeffsOfAPolynomial []frontend.Variable) {
    evalAt0 := polynomials.UniP(coeffsOfAPolynomial, 0, api)
    evalAt1 := polynomials.UniP(coeffsOfAPolynomial, 1, api)
    api.AssertIsEqual(result, api.Add(evalAt0, evalAt1))
}

func checkFirstRound (api frontend.API, circuit *Circuit) {
    assertSumOfEvaluationAt0And1(api, circuit.ComputedSum, circuit.CoeffsOfMiddleUnivariatePolynomials[0])
}

func checkMiddleRounds (api frontend.API, circuit *Circuit, manager *hashmanager.HashManager) {
    manager.WriteInput(circuit.InitialSeed, circuit.ComputedSum)
    for i:=1; i<len(circuit.CoeffsOfMiddleUnivariatePolynomials); i++ {
        hashUntilNow := manager.WriteInputAndCollectAndReturnHash(circuit.CoeffsOfMiddleUnivariatePolynomials[i-1]...)
        evalOfMiddlePolynomialAtAHash := polynomials.UniP(circuit.CoeffsOfMiddleUnivariatePolynomials[i-1], hashUntilNow, api)
        assertSumOfEvaluationAt0And1(api, evalOfMiddlePolynomialAtAHash, circuit.CoeffsOfMiddleUnivariatePolynomials[i])
    }
}

func checkLastRound (api frontend.API, circuit *Circuit, manager *hashmanager.HashManager) {
    hashUntilNow := manager.WriteInputAndCollectAndReturnHash(circuit.CoeffsOfMiddleUnivariatePolynomials[len(circuit.CoeffsOfMiddleUnivariatePolynomials)-1]...)
    evalOfMiddlePolynomialAtAHash := polynomials.UniP(circuit.CoeffsOfMiddleUnivariatePolynomials[len(circuit.CoeffsOfMiddleUnivariatePolynomials)-1], hashUntilNow, api)
    evalOfInitialPolynomialAtAllHashes := polynomials.MultP(circuit.CoeffsOfInitialMultilinearPolynomial, manager.HashCollector, api)
    api.AssertIsEqual(evalOfMiddlePolynomialAtAHash, evalOfInitialPolynomialAtAllHashes)
}

func (circuit *Circuit) Define (api frontend.API) error {
    var manager = hashmanager.NewHashManager(api)
    checkFirstRound(api, circuit)
    checkMiddleRounds(api, circuit, manager)
    checkLastRound(api, circuit, manager)
    return nil
}

func main() {
    var CoeffsOfMiddleUnivariatePolynomials = make([][]frontend.Variable, 3)
    for i:=0;i<3;i++ {
        CoeffsOfMiddleUnivariatePolynomials[i] = make([]frontend.Variable, 2)
    }
    var circuit = Circuit{
        CoeffsOfInitialMultilinearPolynomial: make([]frontend.Variable, 8),
        CoeffsOfMiddleUnivariatePolynomials: CoeffsOfMiddleUnivariatePolynomials,
    }
    ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
    pk, vk, _ := groth16.Setup(ccs)
    G1_0, _ := new(big.Int).SetString("1020204", 10)
    G1_1, _ := new(big.Int).SetString("10202040", 10)
    G2_0, _ := new(big.Int).SetString("482480799671326968966589061680369608414568155496865577406024069086729633310015242", 10)
    G2_1, _ := new(big.Int).SetString("48248079967132696896658906168036960841456815549686557740602406908672963331001524200", 10)
    G3_0, _ := new(big.Int).SetString("88703303929150795986606904465882177409725616560450802144675156296904524300670214609344006370093441889857321811758012908626046938167740756304280941713422321", 10)
    G3_1, _ := new(big.Int).SetString("887033039291507959866069044658821774097256165604508021446751562969045243006702146093440063700934418898573218117580129086260469381677407563042809417134223210000", 10)
    assignment := Circuit{ 
        InitialSeed: 47,
        ComputedSum: 12242448,
        CoeffsOfInitialMultilinearPolynomial: []frontend.Variable{1,10,100,1000,10000, 100000, 1000000, 10000000}, //f(x,y,z) = 1 + 10x + 100y + 1000xy + 10000z + 100000zx + 1000000zy + 10000000zxy
        CoeffsOfMiddleUnivariatePolynomials: [][]frontend.Variable{[]frontend.Variable{G1_0, G1_1}, []frontend.Variable{G2_0, G2_1}, []frontend.Variable{G3_0, G3_1}},
    }
    witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
    publicWitness, _ := witness.Public()
    proof, _ := groth16.Prove(ccs, pk, witness)
    groth16.Verify(proof, vk, publicWitness)
}



