package main

import(
    "github.com/vocdoni/gnark-crypto-primitives/poseidon"
    "github.com/consensys/gnark/frontend/cs/r1cs"
    "github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/frontend"
    "tutorial/sumcheck-verifier-circuit/polynomials"
    "math/big"
)

type Circuit struct {
    Seed frontend.Variable `gnark:"Seed"` 
    C1 frontend.Variable `gnark:"C1"`
    GCoeffs []frontend.Variable `gnark:"G Coefficients"`
    GiCoeffs [][]frontend.Variable `gnark:"G_i Coefficients"`
}

func check01 (api frontend.API, result frontend.Variable, polyCoeffs []frontend.Variable) {
    g0 := polynomials.UniP(polyCoeffs, 0, api)
    g1 := polynomials.UniP(polyCoeffs, 1, api)
    api.AssertIsEqual(result, api.Add(g0, g1))
}

func checkFirstRound (api frontend.API, circuit *Circuit) {
    check01(api, circuit.C1, circuit.GiCoeffs[0])
}

func checkMiddleRounds (api frontend.API, circuit *Circuit, hashes *[]frontend.Variable) {
    var poseidonInstance = poseidon.NewPoseidon(api)
    poseidonInstance.Write(circuit.Seed)
    poseidonInstance.Write(circuit.C1)
    var hash = poseidonInstance.Sum()
    for i:=1; i<len(circuit.GiCoeffs); i++ {
        poseidonInstance.Write(hash)
        poseidonInstance.Write(circuit.GiCoeffs[i-1]...)
        hash = poseidonInstance.Sum()
        *hashes = append(*hashes, hash)
        evalRnd := polynomials.UniP(circuit.GiCoeffs[i-1], hash, api)
        check01(api, evalRnd, circuit.GiCoeffs[i])
    }
}

func checkLastRound (api frontend.API, circuit *Circuit, hashes *[]frontend.Variable) {
    var hash = (*hashes)[len(circuit.GiCoeffs)-2] // Assumes the sum-check function has at least two variables
    var poseidonInstance = poseidon.NewPoseidon(api)
    poseidonInstance.Write(hash)
    poseidonInstance.Write(circuit.GiCoeffs[len(circuit.GiCoeffs)-1]...)
    hash = poseidonInstance.Sum()
    *hashes = append(*hashes, hash)
    evalRnd := polynomials.UniP(circuit.GiCoeffs[len(circuit.GiCoeffs)-1], hash, api)
    evalG := polynomials.MultP(circuit.GCoeffs, *hashes, api)
    api.AssertIsEqual(evalRnd, evalG)
}

func (circuit *Circuit) Define (api frontend.API) error {
    var hashes = []frontend.Variable{}
    checkFirstRound(api, circuit)
    checkMiddleRounds(api, circuit, &hashes)
    checkLastRound(api, circuit, &hashes)
    return nil
}

func main() {
    var GiCoeffs = make([][]frontend.Variable, 2)
    for i:=0;i<2;i++ {
        GiCoeffs[i] = make([]frontend.Variable, 2)
    }
    var circuit = Circuit{
        GCoeffs: make([]frontend.Variable, 4),
        GiCoeffs: GiCoeffs,
    }
    ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
    pk, vk, _ := groth16.Setup(ccs)
    G2_0, _ := new(big.Int).SetString("57641245413269694071184691489861811328223123049926456696620017428154679498982", 10)
    G2_1, _ := new(big.Int).SetString("192137484710898980237282304966206037760743743499754855655400058093848931663277", 10)
    assignment := Circuit{ 
        Seed: 47,
        C1: 34,
        GCoeffs: []frontend.Variable{1,3,7,10}, //evalRnd(x, y) := 1 + 3x + 7y + 10xy
        GiCoeffs: [][]frontend.Variable{[]frontend.Variable{9,16}, []frontend.Variable{G2_0, G2_1}},
    }
    witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
    publicWitness, _ := witness.Public()
    proof, _ := groth16.Prove(ccs, pk, witness)
    groth16.Verify(proof, vk, publicWitness)
}


