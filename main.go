package main

import(
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"tutorial/sumcheck-verifier-circuit/polynomials"
	// "github.com/kr/pretty"
	"math/big"
)

type Circuit struct {
	Seed frontend.Variable `gnark:"Seed"` 
	C1 frontend.Variable `gnark:"C1"`
	R [2]frontend.Variable `gnark:"R"`
	GCoeffs [4]frontend.Variable `gnark:"G Coefficients"`
	GiCoeffs [2][2]frontend.Variable `gnark:"G_i Coefficients"`
}

func check01 (api frontend.API, result frontend.Variable, polyCoeffs []frontend.Variable) {
	g0 := polynomials.UniP(polyCoeffs, 0, api)
	g1 := polynomials.UniP(polyCoeffs, 1, api)
	api.AssertIsEqual(result, api.Add(g0, g1))
}

func checkFirstRound (api frontend.API, circuit *Circuit) {
	check01(api, circuit.C1, circuit.GiCoeffs[0][:])
}

func checkMiddleRounds (api frontend.API, circuit *Circuit) {
	var R = &circuit.R
	var Gi = &circuit.GiCoeffs

	for i:=0; i<len(R)-1; i++ {
		var valToHash = circuit.Seed 
		if (i > 0) { 
			valToHash = R[i-1] 
		}
		api.AssertIsEqual(R[i], poseidon.Hash(api, valToHash))
		evalRnd := polynomials.UniP(Gi[i][:], R[i], api)
		check01(api, evalRnd, Gi[i+1][:])
	}
}

func checkLastRound (api frontend.API, circuit *Circuit) {
	var R = &circuit.R
	var Gi = &circuit.GiCoeffs
	var valToHash = circuit.Seed 
	if (len(R) > 1) { 
		valToHash = R[len(R)-2] 
	}
	api.AssertIsEqual(poseidon.Hash(api, valToHash), R[len(R)-1])
	evalRnd := polynomials.UniP(Gi[len(R)-1][:], R[len(R)-1], api)
	evalG := polynomials.MultP(circuit.GCoeffs[:], R[:], api)
	api.AssertIsEqual(evalRnd, evalG)
}

func (circuit *Circuit) Define (api frontend.API) error {
	checkFirstRound(api, circuit)
	checkMiddleRounds(api, circuit)
	checkLastRound(api, circuit)
	return nil
}

func main() {
	var circuit Circuit 
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(ccs)
	R1, _ := new(big.Int).SetString("9256297558679035993185603119224026483248878132105160101344427504900917382708", 10)
	R2, _ := new(big.Int).SetString("1501086694344315373207989466448958625613689647511317698257372243506299745486", 10)
	G2_0, _ := new(big.Int).SetString("5880649804197832757310403612414804361198269995899445960335078328126943652508", 10)
	G2_1, _ := new(big.Int).SetString("5010004099433259042870408211211164478295323719387463638651458302705939844619", 10)

	assignment := Circuit{ 
		Seed: 47,
		C1: 34,
		GCoeffs: [4]frontend.Variable{1,3,7,10}, //evalRnd(x, y) := 1 + 3x + 7y + 10xy
		R: [2]frontend.Variable{R1, R2},
		GiCoeffs: [2][2]frontend.Variable{[2]frontend.Variable{9,16}, [2]frontend.Variable{G2_0, G2_1}},
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
