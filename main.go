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
    for i:=1; i<len(circuit.GiCoeffs); i++ {
        poseidonInstance.Write(circuit.GiCoeffs[i-1]...)
        hash := poseidonInstance.Sum()
        api.Println(hash)
        *hashes = append(*hashes, hash)
        poseidonInstance.Write(hash)
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
    var GiCoeffs = make([][]frontend.Variable, 3)
    for i:=0;i<3;i++ {
        GiCoeffs[i] = make([]frontend.Variable, 2)
    }
    var circuit = Circuit{
        GCoeffs: make([]frontend.Variable, 8),
        GiCoeffs: GiCoeffs,
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
        Seed: 47,
        C1: 12242448,
        GCoeffs: []frontend.Variable{1,10,100,1000,10000, 100000, 1000000, 10000000}, //evalRnd(x, y) := 1 + 3x + 7y + 10xy
        GiCoeffs: [][]frontend.Variable{[]frontend.Variable{G1_0, G1_1}, []frontend.Variable{G2_0, G2_1}, []frontend.Variable{G3_0, G3_1}},
    }
    witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
    publicWitness, _ := witness.Public()
    proof, _ := groth16.Prove(ccs, pk, witness)
    groth16.Verify(proof, vk, publicWitness)
}


