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
	R []frontend.Variable `gnark:"R"`
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

func checkMiddleRounds (api frontend.API, circuit *Circuit) {
	for i:=0; i<len(circuit.R)-1; i++ {
		var valToHash = circuit.Seed 
		if (i > 0) { 
			valToHash = circuit.R[i-1] 
		}
		api.AssertIsEqual(circuit.R[i], poseidon.Hash(api, valToHash))
		evalRnd := polynomials.UniP(circuit.GiCoeffs[i], circuit.R[i], api)
		check01(api, evalRnd, circuit.GiCoeffs[i+1])
	}
}

func checkLastRound (api frontend.API, circuit *Circuit) {
	var valToHash = circuit.Seed 
	if (len(circuit.R) > 1) { 
		valToHash = circuit.R[len(circuit.R)-2] 
	}
	api.AssertIsEqual(poseidon.Hash(api, valToHash), circuit.R[len(circuit.R)-1])
	evalRnd := polynomials.UniP(circuit.GiCoeffs[len(circuit.R)-1], circuit.R[len(circuit.R)-1], api)
	evalG := polynomials.MultP(circuit.GCoeffs, circuit.R, api)
	api.AssertIsEqual(evalRnd, evalG)
}

func (circuit *Circuit) Define (api frontend.API) error {
	checkFirstRound(api, circuit)
	checkMiddleRounds(api, circuit)
	checkLastRound(api, circuit)
	return nil
}

func main() {
	var GiCoeffs = make([][]frontend.Variable, 2)
	for i:=0;i<2;i++ {
		GiCoeffs[i] = make([]frontend.Variable, 2)
	}
	var circuit = Circuit{
		R: make([]frontend.Variable, 2),
		GCoeffs: make([]frontend.Variable, 4),
		GiCoeffs: GiCoeffs,
	}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(ccs)
	R1, _ := new(big.Int).SetString("9256297558679035993185603119224026483248878132105160101344427504900917382708", 10)
	R2, _ := new(big.Int).SetString("1501086694344315373207989466448958625613689647511317698257372243506299745486", 10)
	G2_0, _ := new(big.Int).SetString("5880649804197832757310403612414804361198269995899445960335078328126943652508", 10)
	G2_1, _ := new(big.Int).SetString("5010004099433259042870408211211164478295323719387463638651458302705939844619", 10)
	assignment := Circuit{ 
		Seed: 47,
		C1: 34,
		GCoeffs: []frontend.Variable{1,3,7,10}, //evalRnd(x, y) := 1 + 3x + 7y + 10xy
		R: []frontend.Variable{R1, R2},
		GiCoeffs: [][]frontend.Variable{[]frontend.Variable{9,16}, []frontend.Variable{G2_0, G2_1}},
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
